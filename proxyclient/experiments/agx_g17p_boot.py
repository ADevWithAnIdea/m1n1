#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bring T8140/G17P firmware up from cold and submit the first work group.

    M1N1DEVICE=/dev/m1n1-neo PYTHONPATH=proxyclient \
        .venv/bin/python3 proxyclient/experiments/agx_g17p_boot.py

Bare metal against a chainloaded m1n1: no macOS guest, no hypervisor, no snapshot
restore of firmware state. Everything firmware is handed is built here.

This is the established path. It has no configuration: every choice in it is one
hardware has settled, and the reasons are in the comments. Its predecessor,
agx_g17p_coldboot.py, accumulated ninety-seven options while those choices were
being found, of which the working configuration used eighteen; the rest select
arrangements hardware has since ruled out, and reading the live path through them
had itself become a source of mistakes. Bisecting a new question belongs there or
in a script of its own, not here.

What it does, in order:

  * powers the accelerator and both coprocessors, and applies the AXI transition
    workaround
  * builds an address space of its own with m1n1's translation-table code, with the
    root table arranged the way a working host's is
  * builds the descriptor root, main configuration object, hardware-data object,
    data region, status blocks, channel state and rings for both firmware instances
  * builds the render context a verified submission draws in, and the context and
    queue state a first submission names
  * stages both instances' device-control opening sequences
  * hands each instance its descriptor, waits for the acknowledgement, and starts
    the control channels
  * publishes one paired tiling/fragment work group and reads the render witness

Where it stands: the group is accepted, consumed, completed and retired, and the
render extent is unchanged afterwards, so firmware schedules the work without
executing it. That is the open question this path exists to close.
"""

import argparse
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import struct
import sys
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.setup import p, u, iface           # noqa: E402
from m1n1.constructutils import Ver          # noqa: E402

# The translation-table layout depends on the accelerator generation, and the module that
# implements it picks a layout at import time, so the generation has to be published from the
# device tree before that import happens. Skipping this leaves the older layout in force, which
# splits the address space one bit lower than this part does: the tables then look self-consistent
# to the host and translate nothing for the coprocessor.
Ver.set_version(u)
if Ver._version.get("V") is None:
    # The host operating system version is only knowable when one is running, and nothing here is.
    # It selects between layouts of structures this script does not build, so the newest known
    # value is a safe stand-in and keeps those definitions importable.
    Ver.set_version_key("V", Ver.MATRIX["V"][-1])

from m1n1.fw.asc import StandardASC          # noqa: E402
from m1n1.fw.asc.base import (ASCBaseEndpoint, ASCTimeout,  # noqa: E402
                              msg_handler)
from m1n1.fw.asc.crash import ASCCrashLogEndpoint, CrashLog  # noqa: E402
from m1n1.fw.asc.mgmt import (ASCManagementEndpoint, Mgmt_EPMap,
                              Mgmt_EPMap_Ack)  # noqa: E402
from m1n1.malloc import Heap                 # noqa: E402
from m1n1.utils import Register64            # noqa: E402
from m1n1.hw.uat import UAT, MemoryAttr      # noqa: E402
from m1n1.agx import g17p                    # noqa: E402
from m1n1.agx import g17p_compute            # noqa: E402
from m1n1.agx import g17p_initdata as build  # noqa: E402
from m1n1.agx import g17p_submission         # noqa: E402
from m1n1.agx.g17p_source_topology import (  # noqa: E402
    G17PSourceTopology,
    native_firmware_leaf_pages,
    native_table_targets,
)

PAGE = 0x4000
ARTIFACTS = pathlib.Path(os.environ.get(
    "G17P_ARTIFACTS",
    os.path.expanduser("~/asahi_re/artifacts/agx_g17p")))
CAPTURE_WRITE_AUDIT = []
CAPTURE_READ_AUDIT = []
STRICT_SOURCE_BOOT = [False]
SOURCE_NATIVE_PHYSICAL_TOPOLOGY = False


def audit_capture_write(source, address, size):
    """Record bytes imported from a captured or replayed hardware world."""
    CAPTURE_WRITE_AUDIT.append({
        "source": str(source),
        "address": int(address),
        "size": int(size),
    })

# The capture this path seeds from. Only content this project cannot generate comes out of it:
# the compiled load and store pipelines, six render input pages, and the bytes of each work
# descriptor past the register array. Everything else is built.
SNAPSHOT = ARTIFACTS / (
    "native_partial_first_app_pre_kick_20260821_020229"
    if os.getenv("G17P_PARTIAL_OPENING_GRAPH") == "1"
    else "pre_work_0x83_v2_20260724_193713"
)
# The same host one work doorbell later. Its firmware context has 32 pages this one does not.
SECOND_SNAPSHOT = ARTIFACTS / "second_0x83_20260729_032917"
# The eight pages added to the firmware context at native queue-pair creation
# that are not already occupied by the pair's generated objects. Hardware dumps
# show every one blank. The other 24 pages in the measured growth are the two
# eight-page queue-context objects and eight pages owned by the explicit pair
# graph, so a driver builds those through their respective allocators.
RUNTIME_PAIR_BLANK_PAGES = (
    (0xfffffc2001638000, MemoryAttr.Shared, 0),
    (0xfffffc2001650000, MemoryAttr.Shared, 0),
    (0xfffffc200165c000, MemoryAttr.Shared, 1),
    (0xfffffc20c087c000, MemoryAttr.Normal, 1),
    (0xfffffc20c088c000, MemoryAttr.Normal, 1),
    (0xfffffc20c0890000, MemoryAttr.Normal, 1),
    (0xfffffc20c0894000, MemoryAttr.Normal, 1),
    (0xfffffc20c08ac000, MemoryAttr.Normal, 1),
)

RUNTIME_PAIR_CONTEXT_ALIASES = (
    (0x7000488000, 0xfffffc2000228000, 8),
    (0x70004b0000, 0xfffffc2000250000, 8),
)
INITIAL_QUEUE_CONTEXT_PAGES = 8

# The translation context every mapping here is made through. Not 0, which the initdata handoff
# owns on a host that has one.
CONTEXT = 1

# How a working host arranges the root table.  The older ordinary-render
# fixture enumerates its render root at slot 7.  The clean first-partial
# snapshot has only slots 0/1/2 and carries the render root in slot 2.  The slot is
# the table position and the context id is the ASID field of the slot's two root pointers, so the
# two are independent, and a work item names the context id rather than the slot. Slot 1 carries
# the firmware context tagged 64 and the selected render slot is tagged 1.
#
# The firmware context uniquely has no low-address root at all: its slot reads root0 = 0. So
# firmware cannot reach the low alias region through its own context and reaches the operand table
# through the render context.
NATIVE_FIRMWARE_SLOT = 1
NATIVE_FIRMWARE_CONTEXT = 64
NATIVE_RENDER_SLOT = (
    2 if os.getenv("G17P_PARTIAL_OPENING_GRAPH") == "1" else 7
)
NATIVE_RENDER_CONTEXT = 1

# The first-doorbell capture has separate blank backing at these root/address
# pairs while the direct builder initially aliases a page carrying content.
# They were found by the exhaustive --scan-blank pass; retain the measured set
# so reproducing the native topology does not reread thousands of blank pages.
NATIVE_DISTINCT_BLANK_PAGES = {
    root: tuple(
        address
        for base in (0x7000438000, 0x7000460000)
        for address in range(base, base + INITIAL_QUEUE_CONTEXT_PAGES * PAGE, PAGE)
    )
    for root in (7, 8, 9, 10)
}

# The August 5 source-built lifecycle predates the exhaustive native-topology
# repair above.  It is nevertheless the only cold-boot world in which the
# complete context-2/class-2 graphics lifecycle has already been proved to
# execute physical renders.  Keep its exact mapping policy available as a
# bounded admission experiment; ordinary DRM-shim boots continue to use the
# measured current topology.
LEGACY_AUG5_DISTINCT_BLANK_PAGES = {
    0: (0x7000004000, 0x7000008000, 0x7000208000),
    7: (0x7000438000, 0x7000460000),
    8: (0x7000438000, 0x7000460000),
    9: (0x7000438000, 0x7000460000),
    10: (0x7000438000, 0x7000460000),
}


def legacy_aug5_topology():
    return os.getenv("G17P_LEGACY_AUG5_TOPOLOGY") == "1"

# Cross-root physical aliases in the original source fixture.  The final-26.6
# compact pair relocates their high peers and overrides this table in its
# experiment module.  These are mapping facts, not captured content.
RENDER_FIRMWARE_ALIASES = {
    0x1000078000: 0xfffffc2001610000,
    0x1000080000: 0xfffffc2001620000,
    0x1000190000: 0xfffffc20c0850000,
    0x1000194000: 0xfffffc20c0854000,
    0x1000198000: 0xfffffc20c0858000,
    0x100019c000: 0xfffffc20c085c000,
    0x10001a8000: 0xfffffc2001630000,
}

# The clean first-partial capture relocates the same seven cross-root
# synchronization/index pages.  These pairs were enumerated by equal physical
# page, not inferred from their contents.  In particular, the accelerator's
# low 0x1000080000 guard is firmware's pool-B slot page: separating them lets
# TA write its 0x20 handoff successfully while firmware waits forever on a
# different, still-zero page.
PARTIAL_OPENING_RENDER_FIRMWARE_ALIASES = {
    0x1000078000: 0xfffffc2001608000,
    0x1000080000: 0xfffffc2001618000,
    0x1000190000: 0xfffffc20c0848000,
    0x1000194000: 0xfffffc20c084c000,
    0x1000198000: 0xfffffc20c0850000,
    0x100019c000: 0xfffffc20c0854000,
    0x10001a8000: 0xfffffc2001628000,
}

# ---------------------------------------------------------------------------
# The render context
# ---------------------------------------------------------------------------

RENDER_CONTEXT_BASE = 0x1000000000

# The parameters of the render whose two register programs this project reproduces byte for byte
# offline, in agx_g17p_validate_render_recipe.py. Everything here is either a dimension or the
# address of an object listed in RENDER_PAGES.
RENDER_PARAMETERS = {
    "width": 2408,
    "height": 1506,
    "context_base": RENDER_CONTEXT_BASE,
    "tilemap": 0x10001b0000,
    "heapmeta": 0x10001b5000,
    "tpc": 0x1000240000,
    "deflake_1": 0x10000682a0,
    "deflake_2": 0x1000068020,
    "deflake_3": 0x1000068000,
    "encoder": 0x1000018000,
    "ta_status": 0x1000078000,
    "store_pipeline_bind": 0,
    "store_pipeline": 0x10001990640,
    "load_pipeline_bind": 0x0007800000000040,
    "load_pipeline": 0x10001990240,
    "scissor_array": 0x100019a0000,
    "depth_bias_array": 0x10001af8000,
    "aux_fb": 0x10001aa8000,
    "fragment_status": 0x10001a8000,
}

# Every render page the two register programs name or the tiler stream binds, with the captured
# leaf's execute permission and where the page's content comes from:
#
#   generate  built here, and checked against the capture before it is used
#   zero      firmware and the accelerator fill it; a fresh page is correct
#   seed      content this project cannot generate, taken from the capture
#
# Fourteen pages, eight with content, 1,610 non-zero bytes, of which 1,463 are the compiled load
# and store pipelines. UXN comes from the captured leaves, where four of the fourteen are
# executable.
RENDER_PAGES = (
    (0x1000000000,  0, "generate",     "bind0"),
    (0x1000018000,  0, "generate", "tiler_stream"),
    (0x1000048000,  0, "generate",     "index_buffer"),
    (0x1000058000,  1, "generate",     "bind1_2_3_4_6_7"),
    (0x1000068000,  1, "generate",     "bind5_and_deflake"),
    (0x1000078000,  1, "zero",     "ta_status"),
    (0x10001990000, 1, "seed",     "load_store_pipelines"),
    (0x100019a0000, 1, "generate", "scissor_array"),
    (0x10001a8000,  1, "zero",     "fragment_status"),
    (0x10001aa8000, 1, "generate",     "aux_fb"),
    (0x10001af8000, 0, "zero",     "depth_bias_array"),
    (0x10001b0000,  1, "zero",     "tilemap"),
    (0x10001b4000,  1, "zero",     "heapmeta"),
    (0x1000240000,  1, "zero",     "tile_parameter_cache"),
    (0x10001970000, 1, "construct", "color_attachment_main"),
    (0x10000020000, 1, "construct", "color_attachment_external"),
    (0x10001960000, 0, "construct", "shader_resource_root"),
    (0x10001bc0000, 1, "construct", "uniform_payload"),
)

# Nine further values in the two register programs would resolve to mapped render pages if they are
# addresses rather than configuration words. Most are recognisably geometry or flags, and
# mappedness is not evidence in this dense context, so this does not claim they are addresses. All
# nine are zero in the capture, so a fresh page is correct either way, and mapping them removes a
# class of translation fault from the first render.
RENDER_GUARD_PAGES = (
    (0x1000008000,  0, "guard_0x8000"),
    (0x100000c000,  0, "guard_0xc000"),
    (0x100002c000,  0, "guard_0x2c000"),
    (0x1000080000,  1, "guard_0x80000"),
    (0x1000100000,  1, "guard_0x100000"),
    (0x1000140000,  1, "guard_0x140000"),
    (0x1000178000,  1, "guard_0x178000"),
    (0x1000300000,  1, "guard_0x300000"),
    (0x1000504000,  1, "guard_0x504000"),
)

# The captured render leaves all carry these, and the four bits that matter are not the firmware
# context's: access permission 2 rather than 1, non-global, and not outer shareable. Mapping them
# the firmware context's way puts the pages behind permissions the accelerator does not have.
RENDER_PAGE_FLAGS = {
    "AttrIndex": MemoryAttr.Shared,
    "AP": 2,
    "AF": 1,
    "nG": 1,
    "SH": 0,
    "OS": 1,
}

# The low alias region, `0x70...`, is part of the render context and its leaves carry the render
# context's attributes, not the firmware context's.
LOW_ALIAS_FLAGS = dict(RENDER_PAGE_FLAGS, PXN=1, UXN=1)

# Which of the objects this path builds a working host maps fully cached rather than inner
# non-cacheable, read from the capture's own leaves: the queue records, the item rings, the shared
# control object, the channel control array, the main configuration object and the work rings are
# `AttrIndex 0`; the queue pointer block, the roots, the data region, the channel state block, the
# private cluster and the context/queue firmware aliases are `AttrIndex 2`.
NORMAL_OBJECT_FLAGS = {"AttrIndex": MemoryAttr.Normal, "AP": 1}
PARTIAL_OPENING_GRAPH = os.getenv("G17P_PARTIAL_OPENING_GRAPH") == "1"

# Which UAT root the selected capture recorded the render context under.
RENDER_SNAPSHOT_ROOT = 2 if PARTIAL_OPENING_GRAPH else 7

# ---------------------------------------------------------------------------
# The context and queue state a first submission names
# ---------------------------------------------------------------------------

# Four objects and about 110 bytes of content between them. Handing the optional items four fresh
# zero pages instead made the scheduler fault on a null dereference while examining the group.
#
#   one page per kind, carrying that kind's work descriptor and queue addresses, seen at a low
#     alias and a firmware alias resolving to one physical page
#   a shared control object, naming the operand table and one further word
#   a channel control array of 0x40-byte records
#
# Fields whose roles are not separated carry the captured value, which is this record's convention
# for such fields; the two addresses are substituted with this path's own.
CONTEXT_QUEUE_DESCRIPTOR_AT = 0x210
CONTEXT_QUEUE_QUEUE_AT = 0x218
CONTEXT_QUEUE_WORDS = {
    "tiling": (
        (0x200, 0x0000000000000004),
        (0x220, 0xffff0c0000000001),
        (0x350, 0x0002380380000003),
        (0x378, 0x003fffffffffffff),
    ),
    "fragment": (
        (0x200, 0x0400040000000004),
        (0x208, 0x004000e000130d40),
        (0x220, 0xffff180000000003),
        (0x228, 0x0000000000000001),
        (0x230, 0x0000010000000000),
        (0x350, 0x0002b00380004c05),
        (0x358, 0x0000100380004c3e),
        (0x360, 0x0000100380004c77),
        (0x368, 0x0000100380004cb0),
        (0x378, 0x003fffffffffffff),
    ),
}

# The clean first-application partial capture starts a new local grid-0/1
# queue generation.  Its context records are not the older init-pair records:
# the namespace tag in +0x200 and three fragment locators differ.  These exact
# source constants are independently checked against the pre-kick snapshot.
if PARTIAL_OPENING_GRAPH:
    CONTEXT_QUEUE_WORDS = {
        "tiling": (
            (0x200, 0x1000000000000004),
            (0x220, 0xffff0c0000000001),
            (0x350, 0x0002380380000003),
            (0x378, 0x003fffffffffffff),
        ),
        "fragment": (
            (0x200, 0x1000040000000004),
            (0x220, 0xffff180000000003),
            (0x228, 0x0000000000000001),
            (0x230, 0x0000010000000000),
            (0x350, 0x0002b00380004c05),
            (0x358, 0x0000800380004c3e),
            (0x360, 0x0000b80380004c77),
            (0x368, 0x0000500380004cb0),
            (0x378, 0x003fffffffffffff),
        ),
    }

# Where each of these objects goes: the capture's own addresses, deliberately. The descriptor tails
# and the optional items name them, several are in the low alias region rather than the firmware
# region, and allocating replacements from one cursor moved two low-region objects into the
# firmware region. Whether they can relocate is a separate question from whether a cold boot can
# build their content, so the addresses are fixed and only the content varies.
CONTEXT_QUEUE_ADDRESSES = {
    "tiling": {"low": 0x7000438000, "high": 0xfffffc20001d8000},
    "fragment": {"low": 0x7000460000, "high": 0xfffffc2000200000},
}

# The shared control object is one object named twice: by the device-control `0x20` entry at its
# `+0x14`, and by every first-work optional item at its `+0x36`. Building it twice, once for each,
# meant firmware registered one copy through the opening sequence while the work referenced the
# other, and a registration naming an object the work does not use cannot bind anything.
#
# Its two phase-dependent fields: the cursor at `+0x48` reads `0x88` before the first `0x20` and
# `0xb0` after, and byte zero of the object its `+0x4c` names reads 1 before and 2 after. A host
# builds the before values and firmware advances them.
SHARED_CONTROL_ADDRESS = 0xfffffc20c0830000
SHARED_CONTROL_INNER_ADDRESS = 0xfffffc2001608000
PARTIAL_OPENING_SHARED_CONTROL_ADDRESS = 0xfffffc20c0828000
PARTIAL_OPENING_SHARED_CONTROL_INNER_ADDRESS = 0xfffffc2001600000
PARTIAL_OPENING_STATUS_ADDRESSES = {
    "ta_status": 0xfffffc2001608000,
    "fragment_status": 0xfffffc2001628000,
}
SHARED_CONTROL_COUNT_AT = 0x48
SHARED_CONTROL_COUNT_BEFORE = 0x88
SHARED_CONTROL_COUNT_AFTER = 0xb0
SHARED_CONTROL_INNER_AT = 0x4c
SHARED_CONTROL_INNER_BEFORE = 1
SHARED_CONTROL_INNER_AFTER = 2
SHARED_CONTROL_WORDS = (
    (0x00, 0x0000000000000001),
    (0x10, 0x0000000000000001),
    (0x18, 0x0004000000000070),
    (0x20, 0x0000110000000000),
    (0x28, 0x0000110000000000),
    (0x30, 0x0000007000208000),
    (0x40, 0x0000000000000004),
    (0x60, 0x0000000000000002),
)

# The queue record's context object is the same object the optional items name as their channel
# control: a working host has both queues' context field and both optional items' `+0x4a` holding
# `0xfffffc20c07b8040`, the channel control array's second record.
CHANNEL_CONTROL_ADDRESS = 0xfffffc20c07b8000
CHANNEL_CONTROL_STRIDE = 0x40
CHANNEL_CONTROL_RECORDS = 2
CHANNEL_CONTROL_ITEM_RECORD = 1
CHANNEL_CONTROL_WORDS = (
    (0x00, 0x000001000000ffff),
    (0x20, 0x0002000000000000),
    (0x30, 0x00000000ff000000),
)

# ---------------------------------------------------------------------------
# Where the submission objects go
# ---------------------------------------------------------------------------

# The firmware context divides cleanly in two: every one of the 494 pages at `0xfffffc20c0......`
# is `AttrIndex 0`, fully cached, and every one of the 132 pages below it is `AttrIndex 2`, inner
# non-cacheable. The attribute follows the region exactly.
#
# Every submission object a working host builds lives in the high one: the queue records at
# `0xc0000000`, the item rings at `0xc0008000`, the two descriptors at `0xc0018000` and
# `0xc00b0000`, the optional items at `0xc0600000`, the event items at `0xc05e8000`, the pools at
# `0xc0868000`, the main object, the work rings, and the shared and channel control objects. The
# low region holds the roots, the data region, the channel state block, the private cluster, the
# queue pointer blocks and the job list.
#
# This heap is above the capture's own span, which ends at `0xfffffc20c0868000`, so it is in the
# right region and collides with nothing the firmware extent maps.
BACKEND_HEAP_VA_BASE = 0xfffffc20c0900000

# The queue pointer blocks are the exception. A working host keeps its two at `0xfffffc2000010000`
# and `0xfffffc2000012870`, `0x2870` apart inside one low-region page, alongside the roots and the
# channel state rather than with the submission objects. The same `0x2870` separates its two item
# rings, so it is the per-queue allocation unit.
# Where a working host keeps them, rather than an address of this path's own. The job list sits at
# an unaligned offset inside the first low-region page, which is also where the two pointer blocks
# are, so the whole group is one page in the capture as well.
QUEUE_POINTER_BLOCK_VA = 0xfffffc2000010000
QUEUE_POINTER_BLOCK_STRIDE = 0x2870

# Both queues of a pair name one job list, not one each. The list is intrusive and the scheduler
# links work onto it, so two lists means the pair's halves are on separate lists and neither can
# see the other's half.
QUEUE_JOB_LIST_VA = 0xfffffc2000000018

# Where the six pages below the record pools and the packed shared object go. Their content this
# path builds byte-exactly, checked offline against the capture, but the backend allocated them from
# its heap, which put all six in the high region and then remapped them fully cached along with the
# queue records and item rings.
#
# A working host splits them by region, and the split is the same one the whole firmware context
# follows: the two index pages are high and cached, while the two pool slot pages, the shared slot
# page and the flag page are **low**, inner non-cacheable. Those four are the four-byte slots the
# pool records name and a single flag word, which is what a counter the accelerator reads looks
# like; handing them over cached leaves the host and the accelerator disagreeing about their value.
LEAF_PAGE_ADDRESSES = {
    "pool_a_slots": 0xfffffc2001600000,
    "shared_slots": 0xfffffc2001618000,
    "pool_b_slots": 0xfffffc2001620000,
    "flag": 0xfffffc2001628000,
    "secondary_index": 0xfffffc20c0840000,
    "primary_index": 0xfffffc20c0850000,
}

# The clean first partial graph is one 0x8000 allocation generation earlier
# than the older bootstrap fixture.  With these addresses, every one of the
# six generated leaf pages and all four generated parent objects compare byte
# exact against the clean pre-kick snapshot.
if PARTIAL_OPENING_GRAPH:
    LEAF_PAGE_ADDRESSES = {
        "pool_a_slots": 0xfffffc20015f8000,
        "shared_slots": 0xfffffc2001610000,
        "pool_b_slots": 0xfffffc2001618000,
        "flag": 0xfffffc2001620000,
        "secondary_index": 0xfffffc20c0838000,
        "primary_index": 0xfffffc20c0848000,
    }

# The queue record's `+0x48`. Described elsewhere as counting up per queue, but both queues of the
# captured pair hold the same value, so it is not a per-queue counter there. Using it makes the
# built record byte-exact against the capture.
QUEUE_UUID_VALUE = 0xa6

# ---------------------------------------------------------------------------
# The work descriptors' full-size records
# ---------------------------------------------------------------------------

# Each work descriptor has two views. The queue parser reads a compact body ending after the
# register array, which is what the builder produces; the context-global locator reads on past it,
# and on hardware a record with nothing there faulted. So the record is extended to its full size,
# with the bytes past the register array taken from the capture: 64 non-zero bytes for tiling, 177
# for fragment.
DESCRIPTOR_TAIL = {
    "tiling": {"captured": 0xfffffc20c0018000, "built": 0x3cc, "native": 0x9c0},
    "fragment": {"captured": 0xfffffc20c00b0000, "built": 0x4cc, "native": 0x2240},
}

# Every address those tails hold, at the offset it is held at. Several are unaligned, which is why
# they are listed rather than found by scanning. Each is rewritten to name this path's own object,
# keeping its offset within the page.
DESCRIPTOR_TAIL_POINTERS = {
    "tiling": (
        (0x0760, 0x7000000060),
        (0x0780, 0x1000240000),
        (0x08a6, 0xfffffc20001c8000),
        (0x08ae, 0xfffffc20c07c0000),
        (0x08fe, 0xfffffc2000024c68),
        (0x0934, 0xfffffc20c0830000),
        (0x0945, 0xfffffc2001610000),
    ),
    "fragment": (
        (0x07a0, 0x70000980a0),
        (0x0ec0, 0x70000987c0),
        (0x15e0, 0x7000098ee0),
        (0x1d00, 0x7000099600),
        (0x1f4e, 0x1000000000),
        (0x1fac, 0x1000000300),
        (0x2140, 0xfffffc20001c8004),
        (0x2148, 0xfffffc20c07c0004),
        (0x2198, 0xfffffc2000024c68),
        (0x21a0, 0xfffffc2000024c70),
        (0x21ce, 0xfffffc20c0830000),
        (0x21df, 0xfffffc2001630000),
    ),
}

# What each captured page a tail names becomes here.
#
#   render     already built by build_render_context at the same address, so left alone
#   self       the descriptor's own low alias; see DESCRIPTOR_LOW_ALIAS
#   shared     the shared control object
#   status     a firmware-context alias of a render status page; the tail carries the second,
#              authoritative status locator, and leaving it captured kept the accelerator's status
#              writes on the captured pages
#   seed       a page of this path's own carrying the captured content
#   fresh      a page of this path's own, zero, as the capture has it
DESCRIPTOR_TAIL_TARGETS = {
    0x1000240000: ("render", None),
    0x1000000000: ("render", None),
    0xfffffc20c0830000: ("shared", None),
    0xfffffc2001610000: ("status", "ta_status"),
    0xfffffc2001630000: ("status", "fragment_status"),
    # The capture maps 306 physical pages at both a low and a firmware device address, and each
    # work descriptor is among them. So the pointers its tail carries into these two pages are the
    # descriptor referring to itself through that alias: the tiling tail's `+0x760` holds its own
    # low alias `+0x60`, and the fragment tail's `+0x7a0`, `+0xec0`, `+0x15e0` and `+0x1d00` hold
    # its own `+0xa0`, `+0x7c0`, `+0xee0` and `+0x1600`. Treating them as unrelated pages and
    # seeding copies points the descriptor at something that is not itself.
    0x7000000000: ("self", "tiling"),
    0x7000098000: ("self", "fragment"),
    0xfffffc2000024000: ("seed", None),
    0xfffffc20001c8000: ("fresh", None),
    0xfffffc20c07c0000: ("fresh", None),
}

# Where each work descriptor's low alias goes. Clear of every page the capture maps.
# The capture's own low aliases. With each descriptor now placed at the capture's own firmware
# address, its alias belongs at the capture's own low address as well, and then the self-references
# the tail already carries are correct as they stand and need no rewriting.
DESCRIPTOR_LOW_ALIAS = {"tiling": 0x7000000000, "fragment": 0x7000098000}

# The capture's own low alias for each descriptor, whose attributes this path copies onto its
# own alias. Both are mapped executable there.
DESCRIPTOR_TAIL_CAPTURED_ALIAS = {"tiling": 0x7000000000,
                                  "fragment": 0x7000098000}

# Where a working host puts every object of the submission graph. The content is already byte-exact
# and the address space already matches; this puts the objects at the same addresses too, so the
# graph is identical in placement as well as in content and nothing that names one of these
# addresses without this path knowing can land on a blank page.
#
# The two work descriptors carry the same builder name, since both halves are item 0, and are
# distinguished by order: the tiling half is built first.
SUBMISSION_ADDRESSES = {
    "queue_record_array": 0xfffffc20c0000000,
    "TA_0_item_ring": 0xfffffc20c0008000,
    "3D_0_item_ring": 0xfffffc20c0008000 + QUEUE_POINTER_BLOCK_STRIDE,
    "work_descriptor_0": (0xfffffc20c0018000, 0xfffffc20c00b0000),
    "fragment_optional_item": 0xfffffc20c0600000,
    "tiling_optional_item": 0xfffffc20c06000c0,
    "fragment_event_item": 0xfffffc20c05e8000,
    "tiling_event_item": 0xfffffc20c05e8040,
    "record_pool_a": 0xfffffc20c0828100,
    "record_pool_b": 0xfffffc20c0838080,
    "descriptor_shared_object": 0xfffffc20c0868000,
    "descriptor_zero_object": 0xfffffc20c083a800,
}

if PARTIAL_OPENING_GRAPH:
    SUBMISSION_ADDRESSES.update({
        "record_pool_a": 0xfffffc20c0820100,
        "record_pool_b": 0xfffffc20c0830080,
        "descriptor_shared_object": 0xfffffc20c0860000,
        "descriptor_zero_object": 0xfffffc20c0832800,
    })

# The default source render fixture models a 32-group created graph.  The
# forced-partial opening binds the smaller context-2 inventory already decoded
# by g17p_submission.build_context2_submission_leaf_pages(): six groups from
# 0x11 followed by two from 0x3c.  A physical replay differential proved that
# the generic primary-index inventory alone makes the later partial command
# retire without drawing, while this eight-group inventory is the native
# before-image.  Keep the specialization explicit so ordinary render fixtures
# retain their existing graph.
if PARTIAL_OPENING_GRAPH:
    SUBMISSION_INDEX_GROUP_RANGES = ((0x11, 6), (0x3c, 2))
    SUBMISSION_SHARED_COUNT = 8
else:
    SUBMISSION_INDEX_GROUP_RANGES = None
    SUBMISSION_SHARED_COUNT = 0x20

# The only bytes of the compact descriptor body this path does not reproduce. Built against the
# capture's own object addresses and register programs, the two bodies are byte-exact apart from
# these nine single bytes, every one of which the builder leaves zero:
#
#   two flags, the fragment record's `+0x50` and `+0x90`, both 1
#   seven small values in two per-kind ranges, 0x47..0x49 for tiling and 0x56..0x59 for fragment
#
# The ranges are what a mid-stream host would hold if they count submissions, so the values here
# are not necessarily what a first submission carries; they may also be firmware writeback rather
# than host input, since the capture is of a world whose previous submission had already run.
# Applying them is a test of whether they are read at all.
DESCRIPTOR_BODY_FIELDS = {
    "tiling": ((0x38, 0x47), (0x3a, 0x49), (0x3c, 0x49)),
    "fragment": ((0x50, 0x01), (0x80, 0x56), (0x82, 0x57), (0x84, 0x57),
                 (0x88, 0x59), (0x90, 0x01)),
}

# The clean first-partial descriptors were captured at their actual first
# publication, rather than after an older queue had already completed.  Five
# lifecycle fields therefore differ from the generic/mature descriptor body:
# two generated one-shot flags are clear and three little-endian scalar bytes
# carry the first-publication values.  Keep this epoch specialization next to
# the other measured descriptor-body fields; it is source data, not a copied
# descriptor page.
if PARTIAL_OPENING_GRAPH:
    DESCRIPTOR_BODY_FIELDS = {
        "tiling": DESCRIPTOR_BODY_FIELDS["tiling"] + (
            (0x0789, 0x08),
            (0x093e, 0xd0),
            (0x093f, 0x91),
        ),
        "fragment": DESCRIPTOR_BODY_FIELDS["fragment"] + (
            (0x215c, 0x00),
            (0x21d8, 0x10),
            (0x21d9, 0xa2),
            (0x222d, 0x00),
        ),
    }

# ---------------------------------------------------------------------------
# Device control
# ---------------------------------------------------------------------------

# The primary's opening sequence: three bare `0x16` entries and then a `0x20`, which registers the
# shared control object. The device-control ring lives inside the main configuration object at
# `+0x4c0`, and the entry the builder models as a scalar field there is really the ring's first
# entry.
#
# The `0x20` entry's `+0x1c` names the operand table and its `+0x24` the slot in it. That page is
# entirely zero before the first `0x20` in the capture, and a mid-stream host has nine entries in
# it, so the slot is firmware's to fill: this maps the table and leaves it empty.
CONTROL_OPERAND_TABLE_VA = 0x0000007000208000
CONTROL_OPERAND_SLOT_OFFSET = 0x440
# The clean first-application partial epoch registers c0828000 with a distinct
# operand destination and count.  These are consumed control inputs and are
# therefore outside both otherwise-exact TA/3D pointer closures.
PARTIAL_CONTROL_OPERAND_SLOT_OFFSET = 0x640
PARTIAL_CONTROL_COUNT = 0x18
# The first-partial compact object is observed after firmware has consumed the
# opening control: its cursor is 0xe0.  Executing the exact count-0x18 record
# advances the source object by 0x18, so the native pre-control value is 0xc8.
PARTIAL_SHARED_CONTROL_COUNT_BEFORE = 0xc8
PARTIAL_SHARED_CONTROL_COUNT_AFTER = 0xe0
# Native compute later registers the same shared-control object against a
# second low table. That publication, not the first CL doorbell, converts the
# active pair record into its CL_0 form.
COMPUTE_BINDING_OPERAND_TABLE_VA = 0x00000070017c0000
COMPUTE_BINDING_PREDECESSOR_SLOT = 0x540
COMPUTE_BINDING_OPERAND_SLOT = 0x580
COMPUTE_CLASS2_SUPPORT_TABLE_VA = 0x0000007001088000

# The operand table's own contents. The pre-work capture has this page entirely empty, which is why
# this path left it so and called the slot firmware's to fill. A world that actually renders has it
# **full**: twenty-two entries, each on the `0x40` stride, each naming a buffer and carrying a flag in
# its top nibble, with the buffers on a regular `0x108000` stride from `0x7000220000`.
#
# Twenty-two buffers of `0x108000` is 23.9 MiB, which is the low alias region's 1,540 pages in the
# render context, so the buffers are memory this path already maps; only the table describing them was
# missing.
CONTROL_OPERAND_BUFFER_BASE = 0x0000007000220000
CONTROL_OPERAND_BUFFER_STRIDE = 0x108000
CONTROL_OPERAND_BUFFER_SIZE = 0x100000
CONTROL_OPERAND_ENTRIES = 22
# The clean first-partial render roots enumerate 28 one-megabyte buffers.
# This is independent of the opening control's 0x18-byte cursor advance.
PARTIAL_CONTROL_OPERAND_ENTRIES = 28
# These generated render-root pages occupy DVAs that also exist in context 0,
# but native backs the context-0 leaves independently and leaves them blank.
# The descriptor at directory page zero is the exception: low_aliases supplies
# context 0 with that descriptor's own body instead of the render directory.
PARTIAL_CONTEXT0_BLANK_RENDER_STATE = frozenset({
    0x7000004000,
    0x7000008000,
    0x700000c000,
    CONTROL_OPERAND_TABLE_VA,
})
# A host's table has 22 entries at its first work doorbell and 24 at its second, the two new ones
# naming buffers at the same 0x108000 stride. Its runtime registration entry names slot 22.
CONTROL_OPERAND_ENTRIES_RUNTIME = 24
CONTROL_OPERAND_SLOT_RUNTIME = 0x580
CONTROL_20_COUNT_RUNTIME = 0x38
# The secondary's own runtime entries, counted off its ring across the same two captures.
SECONDARY_RUNTIME_ENTRIES = 5
SECONDARY_ANNOUNCE_SWEEP = [0]
SECONDARY_CONTROL_START = [False]
SECOND_GROUP_DRIVE = [0]
SECONDARY_CONTROL_BEFORE = [0]
CONTROL_OPERAND_ENTRY_STRIDE = 0x40
CONTROL_OPERAND_SLOT_FLAG = 1 << 60

# The low payload of the `0x84` message that announces a device-control entry. A host's is constant
# and names nothing; it is not a channel number, and sending zero there left every entry unconsumed.
CONTROL_ANNOUNCE_PAYLOAD = 0x11

# The second instance's opening sequence, read from a working world's own control ring: three bare
# `0x2a` entries and then thirteen bare `0x22`, sixteen in all, which is exactly what its
# device-control counters read there.
#
# `0x22` is not in the vocabulary catalogued for the primary. The second instance is a precondition
# for the primary servicing its work channels at all, so what it is asked to do is not incidental.
SECONDARY_CONTROL_SEQUENCE = ((0x2a, 3), (0x22, 13))

# Both instances are told to begin servicing their rings in this order, with this gap. Sending the
# two back to back had one of them emit a crash notification.
CONTROL_START_ORDER = (0, 1)
CONTROL_START_GAP_MS = 12

# An experiment may install the first work publication here when it must occur
# in the native interval between the initial control 0x84 and ring retirement.
FINAL_26_6_FIRST_WORK = None
FINAL_26_6_FIRST_WORK_PREPARE = None
FINAL_26_6_FIRST_WORK_AUDIT = None
# An experiment may temporarily replace the complete staged graph with the
# host-visible state at the earlier half of a paired publication.  The hook is
# called after the complete-graph audit and returns a callback which restores
# the later half immediately before its producer is published.
FINAL_26_6_FIRST_WORK_EARLY_STATE = None
FINAL_26_6_PRE_CONTROL_AUDIT = None
FINAL_26_6_PRE_0X84_AUDIT = None
FINAL_26_6_PRE_INIT_REGISTER_AUDIT = None

# ---------------------------------------------------------------------------
# Scalar fields a working host sets that no pointer walk reaches
# ---------------------------------------------------------------------------

# Found by comparing this world's objects against a working one's rather than by following the
# graph, since none of these is an address. They are applied to the built objects before the
# descriptor is handed over.
MAIN_CONFIG_SCALARS = ((0x32c, 1), (0x344, 0xabcdabcd))
DATA_REGION_SCALARS = ((0x7c, 1), (0x80, 1), (0x9c, 0x3000001d), (0xa0, 0x31000002))


class GpuMsg(Register64):
    TYPE = 63, 48


class InitMsg(GpuMsg):
    TYPE = 63, 48
    INITDATA = 43, 0


class DoorbellMsg(GpuMsg):
    TYPE = 63, 48
    CHANNEL = 15, 0


class FirmwareEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GpuMsg
    SHORT = "fw"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.acked = False
        self.events = 0

    @msg_handler(0x09)
    def init_ack(self, msg):
        print("  [fw] initdata acknowledged: %#x" % int(msg.value))
        self.acked = True
        return True

    @msg_handler(0x42)
    def event(self, msg):
        # Printed rather than only counted, but not treated as a witness: the count tracks how
        # long firmware has been running, not what it did with the work. A ninety-second delay
        # raised eleven of these with nothing submitted.
        self.events += 1
        print("  [fw] event %d: %#x" % (self.events, int(msg.value)))
        return True


class DoorbellEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GpuMsg
    SHORT = "db"


# Reading the crash report is off by default. It is firmware's own diagnostic state, registers and
# a mapping list, and every fault in this record was tracked down with it, but reading it is
# intrusive enough that a run has to ask.
READ_CRASH = False
CRASH_OUTPUT_DIR = None
CRASH_CAPTURE_TAG = "runtime"


class CrashLogEndpoint(ASCCrashLogEndpoint):
    """Keep the crash-buffer handshake, reading the report only on request.

    Also acknowledge a firmware-preallocated buffer the way a working host does, rather than
    offering one of our own.
    """

    def handle_crashed(self, msg):
        callback = getattr(self.asc, "g17p_fatal_callback", None)
        if READ_CRASH:
            size = 0x1000 * msg.SIZE
            data = bytes(self.asc.ioread(msg.DVA, size))
            label = getattr(self.asc, "g17p_name", "graphics")
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            stem = "crash_%s_%s_%s" % (CRASH_CAPTURE_TAG, label, stamp)
            output = CRASH_OUTPUT_DIR or ARTIFACTS
            output.mkdir(parents=True, exist_ok=True)
            raw_path = output / (stem + ".bin")
            raw_path.write_bytes(data)

            # A crash report is hardware-generated diagnostic state. Record only its
            # mailbox histories here: the generic decoder also disassembles faulting
            # firmware code, which is outside this clean-room workflow.
            parsed = CrashLog.parse(data)
            mailboxes = []
            for entry in parsed.entries:
                if entry.type != "Cmbx":
                    continue
                mailbox = {
                    "mailbox_type": int(entry.payload.type),
                    "index": int(entry.payload.index),
                    "messages": [{
                        "endpoint": int(item.endpoint),
                        "message": int(item.message),
                        "timestamp": int(item.timestamp),
                    } for item in entry.payload.messages],
                }
                mailboxes.append(mailbox)
                print("  %s mailbox type=%d index=%d (%d records)" % (
                    label, mailbox["mailbox_type"], mailbox["index"],
                    len(mailbox["messages"])))
                for index, item in enumerate(mailbox["messages"]):
                    print("    #%03d @%#x ep=%#x message=%#018x" % (
                        index, item["timestamp"], item["endpoint"],
                        item["message"]))
            summary_path = output / (stem + ".mailboxes.json")
            summary_path.write_text(json.dumps({
                "format": "m1n1-g17p-crash-mailboxes-v1",
                "asc": label,
                "raw": str(raw_path),
                "mailboxes": mailboxes,
            }, indent=2, sort_keys=True) + "\n")
            self.log("saved clean-room crash state to %s and %s" % (
                raw_path, summary_path))
            self.asc.g17p_fatal_report = str(raw_path)
            self.asc.g17p_fatal_mailboxes = str(summary_path)
            if callback is not None:
                callback(self, msg)
                return True
            raise RuntimeError("ASC firmware reported a crash")
        self.log("firmware crash notification at dva %#x (%#x bytes); "
                 "crash payload intentionally not read" %
                 (msg.DVA, 0x1000 * msg.SIZE))
        if callback is not None:
            callback(self, msg)
            return True
        raise RuntimeError("ASC firmware reported a crash")

    def handle_getbuf(self, msg):
        if not msg.DVA:
            return super().handle_getbuf(msg)
        self.iobuffer_dva = msg.DVA
        self.log("buf prealloc at dva %#x" % self.iobuffer_dva)
        self.send(msg)
        self.started = True
        return True


class ManagementEndpoint(ASCManagementEndpoint):
    """The management-message ordering a working host uses.

    Captured from a live mailbox dialogue: it acknowledges the greeting, starts the crash endpoint
    before acknowledging the map that advertises it, acknowledges the endpoint map, sets the host
    power state, then starts the two graphics endpoints. The generic path inserts a coprocessor
    power-state request that is absent there, and by that point the state it would ask for has
    been reached anyway.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.map_done = False
        self.ap_power_requested = False

    @msg_handler(8, Mgmt_EPMap)
    def EPMap(self, msg):
        advertised = []
        for i in range(32):
            if msg.BITMAP & (1 << i):
                epno = 32 * msg.BASE + i
                advertised.append(epno)
                self.asc.eps.append(epno)
                if self.verbose > 0:
                    self.log("Adding endpoint %#x" % epno)
        if 1 in advertised and 1 not in self.asc.epmap:
            self.asc.start_ep(1)
        self.send(Mgmt_EPMap_Ack(BASE=msg.BASE, LAST=msg.LAST,
                                 MORE=0 if msg.LAST else 1))
        if msg.LAST:
            self.map_done = True
        return True

    def wait_boot(self, timeout=None):
        deadline = time.time() + timeout if timeout is not None else None
        while self.iop_power_state != 0x20 or self.ap_power_state != 0x20:
            self.asc.work()
            crash = self.asc.epmap.get(1)
            if (not self.ap_power_requested and self.map_done
                    and self.iop_power_state == 0x20
                    and crash is not None and crash.started):
                self.boot_done()
                self.ap_power_requested = True
            if deadline is not None and time.time() > deadline:
                raise ASCTimeout("Boot timed out")
        self.log("Startup complete")


class GpuASC(StandardASC):
    ENDPOINTS = {
        0x01: CrashLogEndpoint,
        0x20: FirmwareEndpoint,
        0x21: DoorbellEndpoint,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_ep(0, ManagementEndpoint(self, 0))


class AbsentHandoff:
    """Stand-in for the translation-table handoff.

    The handoff is a mutual-exclusion structure for two agents editing the same translation
    tables, and its lock protocol only completes when firmware publishes its half of a magic
    value. Nothing publishes it here and nothing needs to: on bare metal this script is the only
    agent editing the tables, so the lock has no second party to exclude. The host-owned fields
    are still written, because a working host writes them and both instances map the region.
    """

    def __init__(self):
        self.initialized = True

    def initialize(self):
        pass

    @contextlib.contextmanager
    def lock(self):
        yield

    def prepare_cache_flush(self, addr, size):
        return 0

    def complete_cache_flush(self, slot):
        pass


class NativeLeafLayout:
    """Native physical backing policy derived from snapshot mapping metadata.

    The policy never reads a captured page body.  It only answers whether a
    source-built firmware-high DVA occupied a particular physical page in the
    native partial-render world.  Callers still clear and populate that page
    from their own constructors.

    Table and fixed-carveout pages are deliberately excluded.  Those are
    installed by the UAT/bootstrap path itself and must not be mistaken for
    ordinary arena backing merely because firmware also maps them.
    """

    def __init__(self, manifest, group, label):
        self.label = label
        self.pages = {}
        self.claimed = {}
        table_pages = {int(value) & ~(PAGE - 1)
                       for value in group.get("table_pages", ())}
        fixed = tuple(
            (int(region["pa"]),
             int(region["pa"]) + int(region["size"]),
             region["name"])
            for region in manifest.get("fixed_regions", ()))
        skipped_tables = skipped_fixed = aliases = 0
        for mapping in group["mappings"]:
            if mapping.get("pa") is None:
                continue
            va = int(mapping["va"]) & ~(PAGE - 1)
            pa = int(mapping["pa"]) & ~(PAGE - 1)
            if pa in table_pages:
                skipped_tables += 1
                continue
            if any(low <= pa < high for low, high, _name in fixed):
                skipped_fixed += 1
                continue
            prior = self.pages.setdefault(va, pa)
            if prior != pa:
                raise RuntimeError(
                    "%s native leaf %#x has conflicting PAs %#x/%#x" %
                    (label, va, prior, pa))
        by_pa = {}
        for va, pa in self.pages.items():
            aliases += int(pa in by_pa)
            by_pa.setdefault(pa, va)
        print(
            "  loaded %s native leaf placement: %d DVA pages, %d physical "
            "aliases (%d table and %d fixed-carveout mappings excluded)" %
            (label, len(self.pages), aliases, skipped_tables, skipped_fixed),
            flush=True,
        )

    @classmethod
    def from_source(cls, pages, label):
        """Construct an address-only placement policy from source constants."""
        layout = cls.__new__(cls)
        layout.label = label
        layout.pages = {int(va): int(pa) for va, pa in pages.items()}
        layout.claimed = {}
        aliases = len(layout.pages) - len(set(layout.pages.values()))
        print(
            "  loaded %s source leaf placement: %d DVA pages, %d physical "
            "aliases" % (label, len(layout.pages), aliases),
            flush=True,
        )
        return layout

    def page(self, va):
        return self.pages.get(int(va) & ~(PAGE - 1))

    def span(self, va, size, owner):
        """Claim a wholly described, physically contiguous native span.

        A second arena allocation is never allowed to initialize backing that
        an earlier allocation already owns.  Native aliases are installed by
        the explicit alias constructors later in boot; silently clearing a
        claimed target here would destroy the first object's source bytes.
        """
        if va & (PAGE - 1) or size & (PAGE - 1):
            raise RuntimeError(
                "%s native placement request is not page aligned" % owner)
        targets = [self.pages.get(address)
                   for address in range(va, va + size, PAGE)]
        if not targets or any(value is None for value in targets):
            return None
        if any(targets[index] != targets[0] + index * PAGE
               for index in range(len(targets))):
            return None
        for index, target in enumerate(targets):
            prior = self.claimed.get(target)
            if prior is not None:
                return None
        for index, target in enumerate(targets):
            self.claimed[target] = (va + index * PAGE, owner)
        return targets[0]


class Arena:
    """Host memory mapped into the firmware's address space at chosen addresses."""

    def __init__(self, uat, ctx, base_va, native_layout=None):
        self.uat = uat
        self.ctx = ctx
        self.va = base_va
        self.entries = []
        self.native_layout = native_layout
        self.native_pages = 0

    def allocate_backing(self, va, size, name):
        pa = None
        if self.native_layout is not None:
            pa = self.native_layout.span(va, size, name)
        if pa is None:
            pa = u.memalign(PAGE, size)
            native = False
        else:
            native = True
            self.native_pages += size // PAGE
        return pa, native

    def alloc(self, size, name, data=None):
        size = (size + PAGE - 1) & ~(PAGE - 1)
        va = self.va
        pa, native = self.allocate_backing(va, size, name)
        # Clearing on the target avoids transferring large zero-filled objects over
        # debugUSB.  Only the structured payload, when present, crosses the link.
        p.memset32(pa, 0, size)
        if data is not None:
            iface.writemem(pa, data)
        p.dc_civac(pa, size)
        self.uat.iomap_at(self.ctx, va, pa, size,
                          AttrIndex=MemoryAttr.Shared, AP=1)
        self.va += size
        self.entries.append({"name": name, "va": va, "pa": pa, "size": size})
        print("  %-16s va %#018x  pa %#014x  %#x bytes%s" %
              (name, va, pa, size, "  native PA" if native else ""))
        return va, pa

    def alloc_at(self, va, size, name, data=None, flags=None):
        """Map one object at an exact, possibly subpage-aligned device address."""
        page_va = va & ~(PAGE - 1)
        offset = va - page_va
        span = (offset + size + PAGE - 1) & ~(PAGE - 1)
        page_pa, native = self.allocate_backing(page_va, span, name)
        p.memset32(page_pa, 0, span)
        if data is not None:
            iface.writemem(page_pa + offset, data)
        p.dc_civac(page_pa, span)
        self.uat.iomap_at(self.ctx, page_va, page_pa, span,
                          **(flags or {"AttrIndex": MemoryAttr.Shared, "AP": 1}))
        pa = page_pa + offset
        self.entries.append({"name": name, "va": va, "pa": pa, "size": size})
        print("  %-16s va %#018x  pa %#014x  %#x bytes (exact DVA%s)"
              % (name, va, pa, size, ", native PA" if native else ""))
        return va, pa

    def write(self, pa, data):
        iface.writemem(pa, data)
        p.dc_civac(pa, len(data))

    def physical(self, dva):
        # Most recent mapping first. An address can be covered by more than one entry, because the
        # firmware extent maps every captured page and objects placed afterwards remap some of them
        # at exact addresses. The translation tables give the later mapping, so a lookup that
        # returned the earlier one would write an object's content into the physical page nothing
        # points at any more: measured, that silently blanked five of the six submission leaf pages.
        for record in reversed(self.entries):
            if record["va"] <= dva < record["va"] + record["size"]:
                return record["pa"] + (dva - record["va"])
        return None


class BackendArena:
    """A bump allocator over the arena, shaped the way the backend wants.

    The backend asks for small objects and returns only device addresses; the arena hands out whole
    pages and returns both halves. Carving pages up keeps the allocation count sane, and keeping
    the physical alias lets a write go straight to memory.
    """

    def __init__(self, arena):
        self.arena = arena
        self.pages = []
        self.cursor = 0
        self.base = 0
        self.base_pa = 0

    def alloc(self, size, name="object", align=0x40):
        size = int(size)
        if size > PAGE or align >= PAGE:
            va, pa = self.arena.alloc(size, name)
            self.pages.append((va, pa, size))
            return va
        aligned = (self.cursor + align - 1) & ~(align - 1)
        if not self.pages or aligned + size > PAGE:
            va, pa = self.arena.alloc(PAGE, "backend_heap_%d" % len(self.pages))
            self.pages.append((va, pa, PAGE))
            self.base, self.base_pa, aligned = va, pa, 0
        self.cursor = aligned + size
        return self.base + aligned

    def physical(self, dva):
        for va, pa, size in self.pages:
            if va <= dva < va + size:
                return pa + (dva - va)
        return None

    def write(self, dva, data):
        pa = self.physical(dva)
        if pa is None:
            raise RuntimeError("write to %#x is outside the backend's pages" % dva)
        iface.writemem(pa, bytes(data))
        p.dc_civac(pa & ~(PAGE - 1), PAGE)


def load_backend_modules():
    """Load the backend modules under their own package, once.

    By path rather than by import, because the sibling modules reach each other through a package
    name and the copy already imported as ``m1n1.agx`` carries the older generation's structures.
    """
    if "g17pbackend" in sys.modules:
        return sys.modules["g17pbackend"]

    import importlib.util
    import types

    directory = pathlib.Path(__file__).resolve().parents[1] / "m1n1" / "agx"
    package = types.ModuleType("g17pbackend")
    package.__path__ = [str(directory)]
    sys.modules["g17pbackend"] = package
    for name in ("g17p", "g17p_submission", "g17p_render", "g17p_encoder",
                 "g17p_backend", "g17p_shim"):
        spec = importlib.util.spec_from_file_location(
            "g17pbackend." + name, directory / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules["g17pbackend." + name] = module
        setattr(package, name, module)
        spec.loader.exec_module(module)
    return package


class Capture:
    """The pages of the seed capture, by device address."""

    def __init__(self, snapshot):
        CAPTURE_READ_AUDIT.append(str(snapshot))
        if STRICT_SOURCE_BOOT[0]:
            raise RuntimeError(
                "strict source boot attempted to open snapshot %s" % snapshot)
        manifest = json.loads((snapshot / "manifest.json").read_text())
        self.ram = (snapshot / manifest["ram_file"]).read_bytes()
        self.selected_root = int(manifest["selected_root"]["index"])
        self.blobs = {}
        self.ptes = {}
        self.by_root = {}
        # Native physical backing is part of the mapping topology.  A flat
        # DVA-to-PA map loses this information because the same DVA can name
        # different pages in different contexts.
        self.pa_by_root = {}
        # The physical address each page was captured at. The replay path restores every blob page
        # at its own, so whether the accelerator depends on them is a question this can answer.
        self.pas = {}
        # The ASID each root slot is tagged with, so a rebuilt context carries the same tag.
        self.root_ctx = {}
        for mapping in manifest["mappings"]:
            if mapping.get("blob_index") is not None:
                self.blobs.setdefault(int(mapping["va"]),
                                      int(mapping["blob_index"]))
        for group in manifest["root_mappings"]:
            index = int(group["root_index"])
            root = self.by_root.setdefault(index, {})
            root_pas = self.pa_by_root.setdefault(index, {})
            if group.get("root_ctx_id") is not None:
                self.root_ctx.setdefault(index, int(group["root_ctx_id"]))
            for mapping in group["mappings"]:
                if mapping.get("blob_index") is None:
                    continue
                va = int(mapping["va"])
                root[va] = (int(mapping["blob_index"]), int(mapping["pte"]))
                self.blobs.setdefault(va, int(mapping["blob_index"]))
                self.ptes.setdefault(va, int(mapping["pte"]))
                if mapping.get("pa") is not None:
                    root_pas[va] = int(mapping["pa"]) & ~(PAGE - 1)
                    self.pas.setdefault(va, int(mapping["pa"]) & ~(PAGE - 1))

    def page(self, dva):
        index = self.blobs.get(dva & ~(PAGE - 1))
        if index is None:
            raise RuntimeError("no captured page at %#x" % dva)
        return self.ram[index * PAGE:(index + 1) * PAGE]

    def flags(self, dva, default=None):
        """The mapping attributes the capture gave this page, for iomap_at.

        Content has been matched byte for byte; the translations had not been, and comparing them
        found pages a working host maps **executable** that this path marked never-execute, and one
        it maps fully cached that this path marked inner non-cacheable. The accelerator fetches from
        some of these, so taking the attributes from the capture rather than restating them is both
        more faithful and less to get wrong.
        """
        pte = self.ptes.get(dva & ~(PAGE - 1))
        if pte is None:
            return dict(default or {})
        return self.flags_from_pte(pte)

    def flags_for_root(self, root_index, dva, default=None):
        """Return one root's attributes when DVAs overlap across contexts."""
        record = self.by_root.get(int(root_index), {}).get(
            dva & ~(PAGE - 1)
        )
        if record is None:
            return dict(default or {})
        return self.flags_from_pte(record[1])

    @staticmethod
    def flags_from_pte(pte):
        """The attributes one captured leaf entry carries.

        Taken from a specific entry rather than looked up by address, because a page mapped in
        several contexts can carry different attributes in each: root 0 marks low-alias pages
        executable where root 7 marks the same physical pages never-execute. A flat
        address-to-entry map collapses exactly that distinction.
        """
        return {"AttrIndex": (pte >> 2) & 7, "AP": (pte >> 6) & 3,
                "SH": (pte >> 8) & 3, "AF": (pte >> 10) & 1,
                "nG": (pte >> 11) & 1, "PXN": (pte >> 53) & 1,
                "UXN": (pte >> 54) & 1, "OS": (pte >> 55) & 1}

    def bytes_or_zero(self, dva, size):
        """Captured bytes, with zeros where the capture has no page.

        For grafting, an unmapped page and a blank one are the same thing: nothing to copy.
        """
        out = bytearray()
        while size:
            index = self.blobs.get(dva & ~(PAGE - 1))
            start = dva & (PAGE - 1)
            take = min(size, PAGE - start)
            if index is None:
                out += b"\x00" * take
            else:
                page = self.ram[index * PAGE:(index + 1) * PAGE]
                out += page[start:start + take]
            dva += take
            size -= take
        return bytes(out)

    def bytes(self, dva, size):
        out = b""
        while size:
            body = self.page(dva)
            start = dva & (PAGE - 1)
            take = min(size, PAGE - start)
            out += body[start:start + take]
            dva += take
            size -= take
        return out

    def blob(self, index):
        return self.ram[index * PAGE:(index + 1) * PAGE]


def seed_fixed_regions(snapshot, names):
    """Write the capture's own content into the accelerator's device-tree carveouts.

    These are physical regions outside every UAT root, so nothing the cold path maps covers them,
    and the replay path restores all of them from separate files. The two shared regions are the
    ones a host can usefully seed: `gfx-shared-region` is 512 KiB holding 7,134 non-zero bytes and
    `gfx-shared-l2-region` 16 KiB holding 14. The rest are either this path's own, the coprocessors'
    code and data, or protected.

    Written before the coprocessors start, so firmware sees them as it initialises.
    """
    manifest = json.loads((snapshot / "manifest.json").read_text())
    print("Seeding the accelerator's shared carveouts: %s" % ", ".join(names))
    seeded = []
    for record in manifest["fixed_regions"]:
        if record["name"] not in names:
            continue
        body = (snapshot / record["file"]).read_bytes()
        pa = int(record["pa"])
        try:
            iface.writemem(pa, body)
            p.dc_civac(pa, len(body))
        except Exception as exc:
            # A protected region is a fact about the part, not a reason to lose the run.
            print("  %-22s at %#x refused: %s"
                  % (record["name"], pa, str(exc).splitlines()[0]))
            continue
        audit_capture_write("fixed-region:%s" % record["name"], pa, len(body))
        seeded.append({"name": record["name"], "pa": pa, "size": len(body),
                       "nonzero": sum(byte != 0 for byte in body)})
        print("  %-22s at %#x, %#x bytes, %d non-zero"
              % (record["name"], pa, len(body), seeded[-1]["nonzero"]))
    return seeded


def start_management_coprocessor():
    """Bring the management coprocessor up before the accelerator's firmware starts.

    Firmware reports the first work group complete, writing the done index and a second counter in
    the queue pointer block, while the accelerator never writes a single render page. So it is not
    declining the submission: it believes it ran it. A retirement that succeeds without the
    accelerator executing is what powering the cores down would produce, and power management on this
    platform is the management coprocessor's business. A bare-metal path never completes its handshake
    where a full operating system always has, and the second firmware instance is the power instance.
    """
    from m1n1.fw.smc import SMCClient
    client = SMCClient(u, int(u.adt["arm-io/smc"].get_reg(0)[0]))
    client.verbose = 0
    client.start()
    client.start_ep(0x20)
    print("  management coprocessor up, %d keys"
          % client.epmap[0x20].read32b("#KEY"))
    return client


def graft_firmware_pages(arena, directory, only):
    """Write a rendering world's firmware pages into this one, at the same addresses.

    The graft has only ever run the other way, cold content over a rendering world, which still
    renders. That shows no page this path produces is harmful; it cannot show that none is
    insufficient, because firmware in that world had already read what it needed before the
    overwrite landed.

    Run offline against the capture first: of the 618 firmware pages this path produces, 613 are
    already byte-identical to a rendering world's. The whole of the difference is five pages, so
    this writes very little, and what it writes is nameable.
    """
    directory = pathlib.Path(directory)
    wanted = None
    if only:
        wanted = {int(value, 16) for value in only.split(",") if value.strip()}
    written = []
    for path in sorted(directory.glob("*.bin"), key=lambda item: int(item.stem, 16)):
        dva = int(path.stem, 16)
        if wanted is not None and dva not in wanted:
            continue
        body = path.read_bytes()[:PAGE]
        pa = arena.physical(dva)
        if pa is None:
            print("  %#014x is not mapped here" % dva)
            continue
        existing = iface.readmem(pa, len(body))
        if existing == body:
            continue
        differing = sum(a != b for a, b in zip(existing, body))
        iface.writemem(pa, body)
        p.dc_civac(pa, len(body))
        audit_capture_write("firmware-graft", dva, len(body))
        written.append({"dva": dva, "pa": pa, "differing": differing})
        print("  grafted %#014x at pa %#x, %d bytes replaced" % (dva, pa, differing))
    u.inst("dsb sy")
    print("Grafted %d rendering-world firmware pages over this one's" % len(written))
    return written


def graft_native_firmware_pages(uat, capture, only=None):
    """Make the live firmware context byte-identical to the native first-doorbell snapshot."""
    wanted = None
    if only:
        wanted = {int(value, 16) for value in only.split(",") if value.strip()}
    written = []
    missing = []
    for dva, (blob_index, _pte) in sorted(
            capture.by_root[NATIVE_FIRMWARE_SLOT].items()):
        if wanted is not None and dva not in wanted:
            continue
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, dva)
        if pa is None:
            missing.append(dva)
            continue
        body = capture.blob(blob_index)
        existing = bytes(iface.readmem(pa, PAGE))
        if existing == body:
            continue
        differing = sum(a != b for a, b in zip(existing, body))
        iface.writemem(pa, body)
        p.dc_civac(pa, PAGE)
        audit_capture_write("native-firmware-overlay", dva, PAGE)
        written.append({"dva": dva, "pa": pa, "differing": differing})
        print("  native overlay %#014x at pa %#x, %d bytes replaced"
              % (dva, pa, differing))
    u.inst("dsb sy")
    print("Native first-doorbell overlay replaced %d pages, %d pages unmapped"
          % (len(written), len(missing)))
    return {"written": written, "missing": missing}


# Firmware's two fixed current-job records, which it fills as work completes. A working host leaves them
# zero before its first doorbell and firmware overwrites the same pair for later work. This cold-boot
# path must preseed them for its startup group to run, which is a property of this reconstructed path,
# not part of the native host publication sequence.
#
# The pair lives at PER_SUBMISSION_RECORD_VA, one 0x40-byte record per job in the group, in the same
# order the group's channels are staged. Each record has four significant 64-bit words, two of which
# are addresses
# this path already knows:
#
#     +0x00   a header, constant per stage
#     +0x08   a small constant, 0x20 for tiling and 0x82 for fragment
#     +0x30   the stage's work descriptor
#     +0x38   the queue record the stage submits through
#
# The four values at +0x10, +0x18, +0x20 and +0x28 in a captured record are timestamps. They are not
# required: supplying the structure without them runs the work exactly as supplying the whole record
# does, which is what makes this buildable rather than replayable.
PER_SUBMISSION_RECORD_VA = 0xfffffc20c07d0000
PARTIAL_SECONDARY_SUBMISSION_RECORD_VA = 0xfffffc20c07f8000
PER_SUBMISSION_RECORD_STRIDE = 0x40
PER_SUBMISSION_RECORD_HEADERS = {
    "tiling": (0x0001000000000013, 0x20),
    "fragment": (0x0101000000000223, 0x82),
}
PER_SUBMISSION_DESCRIPTOR_AT = 0x30
PER_SUBMISSION_QUEUE_AT = 0x38


def build_per_submission_records(arena, uat, queues, start=0):
    """Write current-job records for an explicit cold-boot or overwrite experiment."""
    written = []
    for index, (kind, descriptor, queue) in enumerate(queues):
        header, second = PER_SUBMISSION_RECORD_HEADERS[kind]
        written.append({"kind": kind, "descriptor": descriptor, "queue": queue})
        print("  record %d %-8s descriptor %#014x queue %#014x"
              % (start + index, kind, descriptor, queue))
    addresses = [PER_SUBMISSION_RECORD_VA]
    if PARTIAL_OPENING_GRAPH:
        # Each final-26.6 firmware instance owns an independent fixed-record
        # page.  The ordinary source route reached only the primary page; once
        # a partial group reaches the paired scheduler, task 2 selects the
        # secondary page and otherwise cache-maintains a null record pointer.
        addresses.append(PARTIAL_SECONDARY_SUBMISSION_RECORD_VA)
    secondary_fields = os.getenv(
        "G17P_PARTIAL_SECONDARY_RECORD_FIELDS", "all")
    if secondary_fields not in ("all", "header-pointers", "pointers"):
        raise ValueError(
            "G17P_PARTIAL_SECONDARY_RECORD_FIELDS must be all, "
            "header-pointers, or pointers")
    for address in addresses:
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, address)
        if pa is None:
            print("  per-submission record page %#x is not mapped; skipping"
                  % address)
            continue
        page = bytearray(iface.readmem(pa, PAGE))
        for index, (kind, descriptor, queue) in enumerate(queues):
            header, second = PER_SUBMISSION_RECORD_HEADERS[kind]
            base = (start + index) * PER_SUBMISSION_RECORD_STRIDE
            pointers_only = (
                address == PARTIAL_SECONDARY_SUBMISSION_RECORD_VA
                and secondary_fields == "pointers")
            if not pointers_only:
                struct.pack_into("<Q", page, base, header)
            if not (pointers_only or (
                    address == PARTIAL_SECONDARY_SUBMISSION_RECORD_VA
                    and secondary_fields == "header-pointers")):
                struct.pack_into("<Q", page, base + 8, second)
            struct.pack_into("<Q", page,
                             base + PER_SUBMISSION_DESCRIPTOR_AT, descriptor)
            struct.pack_into("<Q", page,
                             base + PER_SUBMISSION_QUEUE_AT, queue)
        iface.writemem(pa, bytes(page))
        p.dc_civac(pa, PAGE)
        description = "per-submission records"
        if address == PARTIAL_SECONDARY_SUBMISSION_RECORD_VA:
            if secondary_fields == "pointers":
                description = "pointer-only secondary records"
            elif secondary_fields == "header-pointers":
                description = "header-and-pointer secondary records"
        print("Built %d %s at %#014x"
              % (len(written), description, address))
    u.inst("dsb sy")
    return written


# A queue pair a working host creates for its submissions after the first, read from the mid-stream
# capture's own queue records. It differs from the pair firmware is given at init in four ways: its
# own pointer block and item ring, the **first** job-list head rather than the second, and a channel
# control address of `0xc07b8000` where the init pair uses `0xc07b8040`.
CREATED_QUEUE_PAIR = (
    {"grid": 2, "kind": "tiling", "record": 0xfffffc20c0000180,
     "pointers": 0xfffffc20000150e0, "ring": 0xfffffc20c000d0e0},
    {"grid": 3, "kind": "fragment", "record": 0xfffffc20c0000240,
     "pointers": 0xfffffc2001658000, "ring": 0xfffffc20c08a8000},
)
CREATED_QUEUE_JOB_LIST = 0xfffffc2000000000
CREATED_QUEUE_CONTEXT = 0xfffffc20c07b8000
# The rest of a created pair's queue record, identical in both of a working host's and in both of
# the init pair's, so they are the record's fixed furniture rather than anything per-queue.
CREATED_QUEUE_RECORD_FIELDS = (
    (0x20, 0xffffffff00000000),
    (0x30, 0xffffffffffff0000),
    (0x38, 0x0000000000000001),
    (0x40, 0xffffffff00000001),
    (0x48, 0x00000000000000a6),
)

# A queue's pointer block carries two host-initialised words besides the indices. Read from a
# working host's created pair at its second doorbell, and identical on its init pair:
#
#     +0x50   0xffffffff
#     +0x60   0x500
#
# This path's created pair got a freshly zeroed page, so it had the write index the submitter writes
# and neither of these. The init pair never showed the gap because its block is seeded from the
# capture.
QUEUE_POINTER_SENTINEL_AT = 0x50
QUEUE_POINTER_SENTINEL = 0xffffffff
QUEUE_POINTER_SIZE_AT = 0x60
QUEUE_POINTER_SIZE = 0x500


def build_created_queue_pair(arena, uat):
    """Write the queue pair a working host creates for its later submissions.

    The earlier attempt at this predates the per-submission records, which are what a first group
    needed before firmware would dispatch it. A created pair without them is in the position the
    first group was in then, so this builds both.
    """
    print("Building the queue pair a working host creates for later submissions")
    # Creating a queue means giving it memory. This world is seeded from the capture taken before a
    # host created any, so the pointer blocks and item rings a created pair uses are not mapped here
    # and have to be allocated.
    for spec in CREATED_QUEUE_PAIR:
        for label in ("pointers", "ring"):
            page = spec[label] & ~(PAGE - 1)
            if leaf_output(uat, NATIVE_FIRMWARE_SLOT, page) is not None:
                continue
            fresh = u.memalign(PAGE, PAGE)
            p.memset32(fresh, 0, PAGE)
            uat.iomap_at(CONTEXT, page, fresh, PAGE, **NORMAL_OBJECT_FLAGS)
            # The submission path reads through the arena rather than the tables, so a page that is
            # mapped but not recorded there is invisible to it.
            arena.entries.append({"name": "created_%s_%d" % (label, spec["grid"]),
                                  "va": page, "pa": fresh, "size": PAGE})

            print("  mapped %s page %#014x for grid %d" % (label, page, spec["grid"]))
    uat.flush_dirty()
    uat.invalidate_cache()
    for spec in CREATED_QUEUE_PAIR:
        page = spec["pointers"] & ~(PAGE - 1)
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, page)
        if pa is None:
            continue
        block = pa + (spec["pointers"] & (PAGE - 1))
        # The init pair's pointer block comes whole from the builder: every index zero and the
        # ring-size word all ones. The created pair's was given two fields and left everything else
        # to whatever was in the page, which after the context growth is a host's own indices, so
        # its write index started at three.
        iface.writemem(block, g17p.build_queue_pointers())
        iface.writemem(block + QUEUE_POINTER_SIZE_AT,
                       struct.pack("<Q", QUEUE_POINTER_SIZE))
        p.dc_civac(pa, PAGE)
        print("  grid %d pointer block built empty, size %#x"
              % (spec["grid"], QUEUE_POINTER_SIZE))
    u.inst("dsb sy")

    # The created pair's queue records name a job-list head of their own, and nothing ever
    # initialised it. The init pair's head is written with the empty circular form, first zero and
    # last the head's own address; this one was left at zero and zero, which is not an empty list
    # but an uninitialised one. Firmware advances only one of its two counters on this pair, so it
    # begins on the group and stops, and an unusable list head is a candidate for where.
    head_pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT,
                          CREATED_QUEUE_JOB_LIST & ~(PAGE - 1))
    if head_pa is not None:
        offset = CREATED_QUEUE_JOB_LIST & (PAGE - 1)
        iface.writemem(head_pa + offset,
                       g17p.build_job_list(CREATED_QUEUE_JOB_LIST))
        p.dc_civac(head_pa, PAGE)
        u.inst("dsb sy")
        print("  created pair's job list head at %#x initialised empty"
              % CREATED_QUEUE_JOB_LIST)

    built = []
    for spec in CREATED_QUEUE_PAIR:
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, spec["record"] & ~(PAGE - 1))
        if pa is None:
            print("  queue record page is not mapped; skipping")
            return []
        offset = spec["record"] & (PAGE - 1)
        # Built by the same builder the init pair's records come from, so the two are constructed
        # identically and differ only in the addresses they name. Writing a chosen subset of the
        # fields by hand left the sentinel, the event id, the priorities and the uuid unset, and a
        # record three-quarters unwritten is not a queue.
        record = bytearray(g17p.build_queue_record(
            pointers_addr=spec["pointers"], ring_addr=spec["ring"],
            job_list_addr=CREATED_QUEUE_JOB_LIST,
            context_addr=CREATED_QUEUE_CONTEXT,
            uuid=QUEUE_UUID_VALUE))
        iface.writemem(pa + offset, bytes(record))
        p.dc_civac(pa, PAGE)
        # The record page resolves to one physical page through the translation tables and, for
        # pages this path allocated itself, another through the arena. Writing only the first leaves
        # everything that reads through the arena, the queue objects among them, seeing zeros. Write
        # both when they differ rather than guessing which one firmware uses.
        arena_pa = arena.physical(spec["record"])
        if arena_pa is not None and (arena_pa & ~(PAGE - 1)) != pa:
            iface.writemem(arena_pa, bytes(record))
            p.dc_civac(arena_pa & ~(PAGE - 1), PAGE)
            print("        record page is aliased: also wrote the arena's copy at %#x"
                  % arena_pa)
        built.append(spec)
        check = bytearray(iface.readmem(pa + offset, g17p.QUEUE_RECORD_SIZE))
        print("  grid %d %-8s record %#014x pointers %#014x ring %#014x"
              % (spec["grid"], spec["kind"], spec["record"], spec["pointers"],
                 spec["ring"]))
        print("        readback job list %#014x context %#014x"
              % (struct.unpack_from("<Q", check, g17p.QUEUE_JOB_LIST_ADDR)[0],
                 struct.unpack_from("<Q", check, g17p.QUEUE_CONTEXT_ADDR)[0]))
    u.inst("dsb sy")
    return built


# The dispatch record, at control operand buffer 21 offset 0x78000. Four `u32` constants, and the
# only thing besides the per-submission records that a cold-booted work group needs in order to run.
# Bisected from the 39-byte input gap: supplying these four and nothing else, with the records built,
# reproduces a working host's accelerator output on 923 of the 943 pages it writes.
DISPATCH_RECORD_VA = 0x7001840000
DISPATCH_RECORD_FIELDS = (
    (0x00, 0xe0000000),
    (0x04, 0x08000000),
    (0x0c, 0x00002c00),
    (0x10, 0x00001600),
)
# The clean first-partial graph has a larger scheduler allocation than the
# older ordinary-render fixture.  Both the context-0 record and its distinct
# firmware-high mirror carry these exact allocation bounds.  They are host
# inputs, not firmware-produced capture state.
PARTIAL_DISPATCH_RECORD_FIELDS = (
    (0x00, 0xe0000000),
    (0x04, 0x08000000),
    (0x0c, 0x00003800),
    (0x10, 0x00001c00),
)
# The aliased resource page is a 0x10-stride record array.  The opening uses
# record zero.  A later partial render is admitted through record two, whose
# host-owned header must exist before firmware sees the command; leaving that
# record zero makes both queues retire normally while the accelerator does no
# work.  The duplicated final words are firmware counters and begin at zero.
INITIAL_RESOURCE_RECORD_FIELDS = (
    (0x00, 0x00019000),
    (0x04, 0x00000080),
    (0x20, 0x00019000),
    (0x24, 0x00000020),
)
PARTIAL_INITIAL_RESOURCE_RECORD_FIELDS = (
    (0x00, 0x00019000),
    (0x04, 0x00000020),
)


def build_dispatch_record(uat):
    """Build the resource headers and dispatch record instead of copying them."""
    fields = (PARTIAL_DISPATCH_RECORD_FIELDS
              if PARTIAL_OPENING_GRAPH else DISPATCH_RECORD_FIELDS)
    resource_va = 0x7001838000
    if not legacy_aug5_topology():
        resource_pa = leaf_output(uat, 0, resource_va)
        if resource_pa is None:
            print("  resource record page is not mapped in context 0; skipping")
            return False
        resource_fields = (PARTIAL_INITIAL_RESOURCE_RECORD_FIELDS
                           if PARTIAL_OPENING_GRAPH
                           else INITIAL_RESOURCE_RECORD_FIELDS)
        for offset, value in resource_fields:
            iface.writemem(resource_pa + offset, struct.pack("<I", value))
        p.dc_civac(resource_pa, PAGE)

    pa = leaf_output(uat, 0, DISPATCH_RECORD_VA)
    if pa is None:
        print("  dispatch record page is not mapped in context 0; skipping")
        return False
    for offset, value in fields:
        iface.writemem(pa + offset, struct.pack("<I", value))
    p.dc_civac(pa, PAGE)
    if PARTIAL_OPENING_GRAPH:
        # In the old source topology the context-0 dispatch page and this
        # firmware-high view were physical aliases.  Native's clean first-
        # partial topology deliberately backs roots 0 and 1 independently,
        # but it publishes the same host-generated record in both views.
        high_va = 0xfffffc20015e8000
        high_pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, high_va)
        if high_pa is None:
            raise RuntimeError(
                "partial dispatch high view %#x is not mapped" % high_va)
        for offset, value in fields:
            iface.writemem(high_pa + offset, struct.pack("<I", value))
        p.dc_civac(high_pa, PAGE)
        print(
            "Mirrored the partial dispatch record into firmware view %#014x" %
            high_va,
            flush=True,
        )
    u.inst("dsb sy")
    if legacy_aug5_topology():
        print("Built the legacy August 5 dispatch record at %#014x: %s"
              % (DISPATCH_RECORD_VA,
                 " ".join("+%#04x=%#010x" % pair
                          for pair in fields)))
    else:
        print("Built the initial scheduler records at %#014x and %#014x: %s"
              % (resource_va, DISPATCH_RECORD_VA,
                 " ".join("+%#04x=%#010x" % pair
                          for pair in fields)))
    return True


# A submission's three work items come from three arrays, each entry the next slot along, measured from
# both queue pairs' item rings across two captures. The two halves have their **own** descriptor arrays
# with different strides, `0x9c0` for tiling and `0x2240` for fragment, and share the optional-item and
# event-item arrays at `0x180` and `0x80`.
WORK_ITEM_STRIDES = {
    "tiling": (0x9c0, 0x180, 0x80),
    "fragment": (0x2240, 0x180, 0x80),
}


def build_fresh_work_items(uat, items, slot, kind):
    """Give a submission its own work items, at the next slot of each array.

    This path had been resubmitting the first group's items, which firmware has already run and
    recorded as complete. A host never does that. The content is copied from the first slot, since
    what a second submission's descriptor should contain is not established; only its address is.
    """
    fresh = []
    for address, stride in zip(items, WORK_ITEM_STRIDES[kind]):
        target = address + slot * stride
        # Page by page. A fragment descriptor is 0x2240 bytes and its slot-2 address sits 0x2240
        # into a page, so a flat copy runs past the end of the physical page and writes over
        # whatever follows it. Reading and writing a span means walking it a page at a time.
        def span(base, size, label):
            out = []
            left = size
            at = base
            while left:
                page = at & ~(PAGE - 1)
                take = min(left, PAGE - (at - page))
                pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, page)
                if pa is None:
                    print("    %s page %#014x not mapped" % (label, page))
                    return None
                out.append((pa + (at - page), take, pa))
                at += take
                left -= take
            return out

        source = span(address, stride, "source")
        destination = span(target, stride, "target")
        if source is None or destination is None:
            fresh.append(address)
            continue
        body = b"".join(bytes(iface.readmem(pa, take)) for pa, take, _ in source)
        at = 0
        for pa, take, page_pa in destination:
            iface.writemem(pa, body[at:at + take])
            p.dc_civac(page_pa, PAGE)
            at += take
        fresh.append(target)
    u.inst("dsb sy")
    return fresh


# What a host advances in a descriptor from one submission to the next, measured by diffing a working
# host's descriptors:
#
#   counters      0 -> 1        a submission ordinal
#   sequences     0x100 -> 0x101  the role stamps play in the M1 and M2 driver in this tree
#   self-relative addresses advance by that half's descriptor stride
#   pool-record pointers advance within the two persistent record arrays
#
# The packed and zero shared objects stay fixed across the captured stream. Render targets change
# because the work differs and are not a mechanical transform of the first descriptor.
DESCRIPTOR_BUMPS = {
    "tiling": {
        "counters": (0x18, 0x48, 0x304),
        "sequences": (0x370, 0x37c, 0x388),
        "self_relative": (),
        "pointers": ((0x10, 0x200), (0x28, 0x80)),
        "stride": 0x9c0,
    },
    "fragment": {
        "counters": (0x458,),
        "sequences": (0x470, 0x47c),
        "self_relative": (0x7a0, 0xec0, 0x15e0, 0x1d00),
        "pointers": ((0x20, 0x200), (0x30, 0x80)),
        "stride": 0x2240,
    },
}


# The submit sequence at descriptor +0x04 advances by two every two submissions, one per queue pair,
# because a host issues both submissions of a round while the first is still in flight. This path
# issues its second only after the first has completed, so from firmware's side that is the next
# round, and the sequence should be the next value rather than a repeat of one it has retired.
SUBMIT_SEQUENCE_AT = 0x04
SUBMIT_SEQUENCE_STEP = 2


def bump_submit_sequence(uat, descriptor, kind):
    """Advance a descriptor's submit sequence to the next round's value."""
    page = descriptor & ~(PAGE - 1)
    pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, page)
    if pa is None:
        return
    where = pa + ((descriptor + SUBMIT_SEQUENCE_AT) & (PAGE - 1))
    value = struct.unpack("<Q", bytes(iface.readmem(where, 8)))[0]
    iface.writemem(where, struct.pack("<Q", value + SUBMIT_SEQUENCE_STEP))
    p.dc_civac(pa, PAGE)
    u.inst("dsb sy")
    print("    %-8s submit sequence %d -> %d"
          % (kind, value, value + SUBMIT_SEQUENCE_STEP))


def bump_descriptor(uat, descriptor, kind, advance_pools=True):
    """Advance the fields a host advances between submissions."""
    spec = DESCRIPTOR_BUMPS[kind]
    page = descriptor & ~(PAGE - 1)
    pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, page)
    if pa is None:
        print("    %#014x not mapped" % descriptor)
        return
    changed = []
    for group, step in (("counters", 1), ("sequences", 1),
                        ("self_relative", spec["stride"])):
        for offset in spec[group]:
            at = descriptor + offset
            at_page = at & ~(PAGE - 1)
            at_pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, at_page)
            if at_pa is None:
                continue
            where = at_pa + (at & (PAGE - 1))
            value = struct.unpack("<I", bytes(iface.readmem(where, 4)))[0]
            iface.writemem(where, struct.pack("<I", value + step))
            p.dc_civac(at_pa, PAGE)
            changed.append((offset, value, value + step))
    if advance_pools:
        for offset, step in spec["pointers"]:
            at = descriptor + offset
            at_page = at & ~(PAGE - 1)
            at_pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, at_page)
            if at_pa is None:
                continue
            where = at_pa + (at & (PAGE - 1))
            value = struct.unpack("<Q", bytes(iface.readmem(where, 8)))[0]
            iface.writemem(where, struct.pack("<Q", value + step))
            p.dc_civac(at_pa, PAGE)
            changed.append((offset, value, value + step))
    u.inst("dsb sy")
    print("    %-8s %s" % (kind, " ".join("+%#x %#x->%#x" % row for row in changed)))


def power_on(sgx):
    """Power the accelerator and both coprocessors, and apply the AXI workaround."""
    print("Powering the accelerator and its coprocessors")
    for path in ("/arm-io/gfx-asc", "/arm-io/gfx1-asc", "/arm-io/sgx"):
        p.pmgr_adt_power_enable(path)
    sgx_base = int(sgx.get_reg(0)[0])
    for offset in (0x1000104, 0x1000108):
        addr = sgx_base + offset
        p.write32(addr, int(p.read32(addr)) | 1)
    # The values a working host leaves in these two after its read-modify-write. If this host's
    # writes land somewhere else, the accelerator is configured differently before firmware starts.
    observed = [int(p.read32(sgx_base + off)) for off in (0x1000104, 0x1000108)]
    print("  applied the AXI transition workaround at %#x, registers now %s"
          % (sgx_base, " ".join("%#010x" % v for v in observed)))
    for got, want in zip(observed, (0x00010001, 0x000413b1)):
        if got != want:
            print("    NOTE: %#010x differs from the recorded %#010x" % (got, want))
    return sgx_base


def create_coprocessors(uat, verbose=0):
    """Start both firmware instances.

    There are two, not one, and the start sequence addresses both. A host that brings up only the
    primary gets a descriptor acknowledged and then nothing further: its work channels are never
    serviced. The graphics endpoints are started later, just before each instance is handed its
    descriptor, which is where a working host starts them.
    """
    # Both objects are constructed before either is booted, as they were when this sequence was
    # established; construction touches the mailbox registers.
    ascs = []
    for path in g17p.COPROCESSOR_NODES[:2]:
        instance = GpuASC(u, int(u.adt[path].get_reg(0)[0]), dart=uat, stream=CONTEXT)
        instance.g17p_name = path.rsplit("/", 1)[-1]
        instance.verbose = verbose
        instance.mgmt.verbose = verbose
        ascs.append(instance)
    return ascs


def start_coprocessors(ascs, verbose=0):
    """Start both cores, once whatever they are to be handed already exists in memory.

    The replay path restores its world, work items and all, and only then starts the cores, so the
    work is present before firmware runs its first instruction. This path had the cores running long
    before it built anything. The record's rule is that work present when firmware starts executes and
    work published afterwards does not, so which side of the core start the staging falls on is not a
    detail.
    """
    for path, instance in zip(g17p.COPROCESSOR_NODES[:2], ascs):
        base = int(u.adt[path].get_reg(0)[0])
        control = int(p.read32(base + 0x0044))
        status = int(p.read32(base + 0x0048))
        print("  %s before start: CPU_CONTROL=%#x (run=%d) CPU_STATUS=%#x "
              "(running=%d stopped=%d idle=%d)"
              % (path, control, (control >> 4) & 1, status,
                 status & 1, (status >> 1) & 1, (status >> 5) & 1))
        instance.boot()
        instance.mgmt.wait_boot(3)
        print("  %s running" % path)
    return ascs


def sample_shared_root(uat, label):
    """Which entries the shared upper root holds, and who put them there.

    That root lives in the accelerator's `gfx-shared-region` carveout and is shared with firmware.
    m1n1's own initializer clears it from index 2 onward, and this path starts the coprocessors before
    it initializes, so anything firmware publishes as it boots is present when that clear happens.
    Whether firmware has entries there, and whether they survive, has never been measured here.
    """
    entries = list(struct.unpack("<64Q", iface.readmem(uat.ttbr1_base, 64 * 8)))
    present = [(index, value) for index, value in enumerate(entries) if value]
    print("  shared upper root at %#x %s: %d of 64 entries present%s"
          % (uat.ttbr1_base, label, len(present),
             "" if not present else
             "  " + ", ".join("[%d]=%#x" % (i, v) for i, v in present[:8])))
    return {index: value for index, value in present}


def bind_contexts(uat, macos_table=False):
    """Bind the translation context and arrange the root table as a working host's is.

    Both slots keep both roots for now. Every mapping this path makes goes through ``CONTEXT`` and
    both slots point at the same two table hierarchies, so the mappings have to be created while
    both roots are reachable and the split applied once building is done; splitting here made 98
    render mappings stop resolving.
    """
    uat.bind_context(CONTEXT, uat.ttbr0_base)
    # Context 0 is in use in a working world and this path had never created it. Its root covers
    # 299 pages, every one of them in the low alias region, and among them is the operand table the
    # device-control `0x20` entry names. So the entry's address belongs to context 0, not to the
    # firmware context, which is why leaving the low root on the firmware slot made the binding work:
    # that was standing in for a context that was simply missing. m1n1's bind_context refuses this
    # context deliberately, so the root pointer is set directly.
    uat.set_l0(0, 0, uat.ttbr0_base, 0)
    uat.set_l0(NATIVE_FIRMWARE_SLOT, 0, uat.ttbr0_base, NATIVE_FIRMWARE_CONTEXT)
    uat.set_l0(NATIVE_FIRMWARE_SLOT, 1, uat.ttbr1_base, NATIVE_FIRMWARE_CONTEXT)
    uat.set_l0(NATIVE_RENDER_SLOT, 0, uat.ttbr0_base, NATIVE_RENDER_CONTEXT)
    uat.set_l0(NATIVE_RENDER_SLOT, 1, uat.ttbr1_base, NATIVE_RENDER_CONTEXT)
    if macos_table:
        # What a working host's hardware context table actually holds, read from the captured
        # gpu-region: exactly two entries, slot 0 tagged 0 and slot 1 tagged 1, the latter being the
        # render context. The firmware context is not in that table at all; firmware takes its own
        # root from the descriptor it is handed. This path had the firmware context at slot 1 tagged
        # 64 and the render context at slot 7, which is the manifest's enumeration order rather than
        # the hardware's.
        for index in range(uat.NUM_CONTEXTS):
            p.write64(uat.gpu_region + index * 16, 0)
            p.write64(uat.gpu_region + index * 16 + 8, 0)
        uat.set_l0(0, 0, uat.ttbr0_base, 0)
        uat.set_l0(0, 1, uat.ttbr1_base, 0)
        uat.set_l0(1, 0, uat.ttbr0_base, 1)
        uat.set_l0(1, 1, uat.ttbr1_base, 1)
        uat.flush_dirty()
        uat.invalidate_cache()
        print("  hardware context table as a working host has it: slot 0 tagged 0, "
              "slot 1 tagged 1, nothing else")
        return

    uat.flush_dirty()
    uat.invalidate_cache()
    print("  slot %d tagged %d for firmware, slot %d tagged %d for the render context"
          % (NATIVE_FIRMWARE_SLOT, NATIVE_FIRMWARE_CONTEXT,
             NATIVE_RENDER_SLOT, NATIVE_RENDER_CONTEXT))


def mirror_secondary_top_table(uat):
    """Copy the host's top-table entries into the second instance's own copy of that table.

    The second instance walks its own copy, in its own half of the shared region, rather than the
    primary's. Entries the host makes in the primary's table have to be mirrored there or the
    secondary translates nothing it is handed, and it crashes instead of acknowledging. Its own
    first entries describe its code and data and are left alone.

    Called once every mapping exists, so nothing made later is missed.
    """
    secondary_root = uat.ttbr1_base + g17p.SECONDARY_SHARED_DELTA
    mirrored = 0
    for index in range(uat.LEVELS[1][1]):
        entry = int(p.read64(uat.ttbr1_base + 8 * index))
        if not entry or index < g17p.SHARED_FIRMWARE_ENTRIES:
            continue
        if int(p.read64(secondary_root + 8 * index)) != entry:
            p.write64(secondary_root + 8 * index, entry)
            mirrored += 1
    p.dc_civac(secondary_root, PAGE)
    print("  mirrored %d top-table entries into the secondary's table at %#x"
          % (mirrored, secondary_root))
    return secondary_root


def native_table_topology(manifest, group):
    """Return captured table PAs indexed only by their address-space path.

    This consumes mapping metadata and physical addresses, not captured table
    bytes.  The snapshot writer records pages in the same deterministic order
    used by replay's table reconstructor: root, then each L1 child followed by
    that child's L2 descendants.
    """
    shift = int(manifest["vaddr_shift"])
    l1_mask = (1 << max(0, shift - 36)) - 1
    tree = {}
    for mapping in group["mappings"]:
        raw = int(mapping["va"]) & ((1 << (shift + 1)) - 1)
        l1_index = (raw >> 36) & l1_mask
        l2_index = (raw >> 25) & 0x7ff
        tree.setdefault(l1_index, set()).add(l2_index)

    pages = [int(value) for value in group["table_pages"]]
    expected = 1 + len(tree) + sum(len(values) for values in tree.values())
    if len(pages) != expected:
        raise RuntimeError(
            "native table topology has %d pages, expected %d" %
            (len(pages), expected))
    targets = {(): pages[0]}
    cursor = 1
    for l1_index in sorted(tree):
        targets[(l1_index,)] = pages[cursor]
        cursor += 1
        for l2_index in sorted(tree[l1_index]):
            targets[(l1_index, l2_index)] = pages[cursor]
            cursor += 1
    return targets


def rebase_source_table_tree(uat, source_root, native_targets, label):
    """Place source-built tables at matching native physical addresses.

    Table bodies are read exclusively from the live source hierarchy.  Child
    pointers are rewritten to the destination selected for that same topology
    path; leaf PTEs are copied bit-for-bit.  Source-only branches retain their
    existing PA, so a topology mismatch cannot silently discard mappings.
    """
    source = {}

    def collect(table_pa, level, path, ancestors):
        if table_pa in ancestors:
            raise RuntimeError(
                "%s UAT table cycle at %#x" % (label, table_pa))
        body = bytes(iface.readmem(table_pa, PAGE))
        source[path] = (table_pa, level, body)
        if level + 1 >= len(uat.LEVELS):
            return
        _offset, count, pte_type = uat.LEVELS[level]
        for index in range(count):
            pte = pte_type(struct.unpack_from("<Q", body, index * 8)[0])
            if not pte.valid() or pte.block():
                continue
            collect(
                pte.offset(), level + 1, path + (index,),
                ancestors | {table_pa})

    collect(int(source_root), 1, (), set())
    destinations = {
        path: int(native_targets.get(path, values[0]))
        for path, values in source.items()
    }
    reverse = {}
    for path, destination in destinations.items():
        prior = reverse.setdefault(destination, path)
        if prior != path:
            raise RuntimeError(
                "%s UAT paths %r and %r collide at %#x" %
                (label, prior, path, destination))

    expected_bodies = {}
    leaf_entries = 0
    table_links = 0
    for path, (_source_pa, level, original) in source.items():
        body = bytearray(original)
        _offset, count, pte_type = uat.LEVELS[level]
        if level + 1 < len(uat.LEVELS):
            for index in range(count):
                offset = index * 8
                pte = pte_type(struct.unpack_from("<Q", body, offset)[0])
                if not pte.valid() or pte.block():
                    continue
                child = path + (index,)
                if child not in destinations:
                    raise RuntimeError(
                        "%s UAT source omits child path %r" % (label, child))
                pte.set_offset(destinations[child])
                struct.pack_into("<Q", body, offset, int(pte))
                table_links += 1
        else:
            leaf_entries += sum(
                pte_type(struct.unpack_from("<Q", body, index * 8)[0]).valid()
                for index in range(count))
        expected_bodies[destinations[path]] = bytes(body)

    for destination, body in expected_bodies.items():
        iface.writemem(destination, body)
        p.dc_civac(destination, PAGE)
    for destination, body in expected_bodies.items():
        if iface.readmem(destination, PAGE) != body:
            raise RuntimeError(
                "%s source UAT table did not read back at %#x" %
                (label, destination))

    uat.invalidate_cache()
    uat.invalidate_root_walk_cache()
    placed = sum(path in native_targets for path in source)
    missing = len(set(native_targets) - set(source))
    print(
        "  rebased %s source UAT hierarchy: root %#x, %d tables, "
        "%d at native PAs, %d source-only, %d native-only paths, "
        "%d links, %d leaf PTEs" % (
            label, destinations[()], len(source), placed,
            len(source) - placed, missing, table_links, leaf_entries),
        flush=True,
    )
    return destinations[()]


def build_captured_contexts(arena, uat, capture, render_state, low_aliases=()):
    """Build every captured context this path does not already provide, with its own table.

    Context 0 is populated in a working world with 299 pages, every one in the low alias region, and
    it maps them **executable** where root 7 maps the same physical pages never-execute. One shared
    table cannot hold both, so this path had been giving context 0 whatever root 7 said; comparing
    leaf attributes is what surfaced it.

    Context 0's pages are aliases, not copies.  Native physical topology shows
    every one of its 299 low pages aliases exactly one firmware-high page.  The
    low and high DVAs differ, so choosing the page at the same low DVA from the
    render context creates the wrong alias.  Resolve the native physical peer
    first, then use the page currently backing that firmware-high DVA.
    """
    # Built from the arena in order, so a later placement wins. The render extent is bulk backing
    # and is itself an arena entry; the specific objects placed afterwards are what an address in
    # another context should resolve to. Letting the extent win, which setdefault did, gave context 0
    # the extent's blank page in place of every object this path had deliberately put there.
    mapped = {}
    for record in arena.entries:
        base = record["va"] & ~(PAGE - 1)
        for offset in range(base, record["va"] + record["size"], PAGE):
            mapped[offset] = (record["pa"] - (record["va"] - base)
                              + (offset - base))

    legacy = legacy_aug5_topology()
    firmware_va_by_native_pa = {}
    if not legacy:
        for high_va in capture.by_root.get(NATIVE_FIRMWARE_SLOT, {}):
            native_pa = capture.pa_by_root.get(
                NATIVE_FIRMWARE_SLOT, {}).get(high_va)
            if native_pa is not None:
                firmware_va_by_native_pa[native_pa] = high_va

    built = []
    for index in sorted(capture.by_root):
        # The clean first-partial host has no old auxiliary slots at all.  Slot
        # zero is still reconstructed below; slots 1 and 2 are this path's own
        # firmware and render contexts.
        if (PARTIAL_OPENING_GRAPH and
                index not in (0, NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT)):
            continue
        # The firmware and render contexts are already built.
        if index in (NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT):
            continue
        pages = capture.by_root[index]
        if not pages:
            continue
        # A physical page. uat.allocator hands out device addresses in the firmware range, not
        # physical ones, and writing through one of those reaches nothing.
        root = u.memalign(PAGE, PAGE)
        p.memset32(root, 0, PAGE)
        ctx_id = capture.root_ctx.get(index, index)
        uat.set_l0(index, 0, root, ctx_id)
        aliased = fresh = 0
        for va in sorted(pages):
            pa = None
            high_peer = None
            distinct_copy = False
            if index == 0:
                if legacy:
                    # This is the exact policy in the source-built world that
                    # ran the August 5 lifecycle: only explicitly constructed
                    # low aliases win before the same-DVA arena lookup. Eight
                    # pages consequently receive fresh backing instead of
                    # being paired with later-discovered native high peers.
                    if va in low_aliases:
                        pa = low_aliases[va][0]
                else:
                    # Context 0 is a low-address view of pages in the captured
                    # firmware tree.  This is true for all 299
                    # leaves in the clean first-partial capture as well as the
                    # older profile.  Preserve the two roots' distinct PTE
                    # attributes, but resolve them to the same source-built
                    # physical pages exactly as native does.
                    native_pa = capture.pa_by_root.get(index, {}).get(va)
                    high_peer = firmware_va_by_native_pa.get(native_pa)
                    if high_peer is None:
                        raise RuntimeError(
                            "native context-0 page %#x has no firmware-high "
                            "physical peer" % va)
                    pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, high_peer)
                    if pa is None:
                        raise RuntimeError(
                            "firmware-high peer %#x for context-0 page %#x is "
                            "not mapped" % (high_peer, va))
                    if va in low_aliases:
                        explicit_pa = low_aliases[va][0] & ~(PAGE - 1)
                        if explicit_pa != pa:
                            raise RuntimeError(
                                "explicit context-0 alias %#x -> %#x "
                                "disagrees with native high peer %#x -> %#x" %
                                (va, explicit_pa, high_peer, pa))
            if pa is None:
                pa = mapped.get(va)
            if pa is None:
                # The private zero page every root carries sits at a distinct physical page per root
                # in a working world, so a fresh one is right rather than an alias.
                pa = u.memalign(PAGE, PAGE)
                p.memset32(pa, 0, PAGE)
                fresh += 1
            elif not distinct_copy:
                aliased += 1
            uat.iomap_at(index, va, pa, PAGE,
                         **capture.flags_from_pte(pages[va][1]))
        built.append({"slot": index, "ctx_id": ctx_id, "root": root,
                      "pages": len(pages), "aliased": aliased, "fresh": fresh})
        print("  slot %-2d tagged %-5d table %#x: %d pages, %d aliased, %d fresh"
              % (index, ctx_id, root, len(pages), aliased, fresh))
    uat.flush_dirty()
    uat.invalidate_cache()
    return built



def apply_context_split(uat, keep_render_high=True):
    """Take the low root off the firmware slot and the high root off the render slot.

    Which is how a working host's root table reads. The tables themselves are untouched; only
    which slot can reach each half changes. Called after every mapping exists.
    """
    # Only the firmware context loses a root. A working host's render context keeps both: its
    # roots list has the firmware context's low root at zero, which is what makes that one
    # distinctive, and the render context's high root at a real address whose table happens to hold
    # no mappings. Zeroing it here gave the render context no high root where a working host gives
    # it an empty one, which are different things to a walker.
    uat.set_l0(NATIVE_FIRMWARE_SLOT, 0, 0, NATIVE_FIRMWARE_CONTEXT)
    if not keep_render_high:
        uat.set_l0(NATIVE_RENDER_SLOT, 1, 0, NATIVE_RENDER_CONTEXT)
    uat.flush_dirty()
    uat.invalidate_cache()
    print("Applied the context split: firmware slot %d has no low root, render slot %d %s"
          % (NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT,
             "keeps its high root, as a working host has it" if keep_render_high
             else "no high root"))


def build_initdata(arena, uat, kern_va_base, count=2):
    """Build every object the two descriptors name, in the layout a working host uses."""
    legacy = legacy_aug5_topology()
    private_cluster_va, private_cluster_pa = arena.alloc_at(
        kern_va_base + g17p.NATIVE_PRIVATE_CLUSTER_OFFSET,
        g17p.NATIVE_PRIVATE_CLUSTER_SIZE, "native_private_state")
    fwctl_va = kern_va_base + g17p.NATIVE_FWCTL_OFFSET
    fwctl_pa = None
    if not legacy:
        fwctl_va, fwctl_pa = arena.alloc_at(
            fwctl_va, PAGE, "firmware_control_ring")

    print("Allocating and building the descriptor objects")
    hwdata_va, hwdata_pa = arena.alloc(g17p.NATIVE_SHARED_CLUSTER_SIZE,
                                       "hwdata_bundle")
    repeated_va = hwdata_va + g17p.MAIN_REPEATED_ADDR_OFFSET

    # Firmware reaches its own registers through the table in the hardware-data object, not through
    # any fixed address, so the windows have to be both mapped into the address space and declared
    # in the table. Two windows are not granule aligned; they share an offset within their page, so
    # mapping the containing page places them correctly.
    register_entries = {}
    for slot, phys, device_va, size, unk_18, flag in g17p.REGISTER_WINDOWS:
        page_phys = phys & ~(PAGE - 1)
        page_va = device_va & ~(PAGE - 1)
        span = (((device_va + size) - page_va) + PAGE - 1) & ~(PAGE - 1)
        uat.iomap_at(CONTEXT, page_va, page_phys, span,
                     AttrIndex=MemoryAttr.Device, AP=1)
        register_entries[slot] = {"phys": phys, "device_va": device_va,
                                  "size": size, "flag": flag, "unk_18": unk_18}
    uat.flush_dirty()
    print("  mapped %d register windows, %d further slots declared empty"
          % (len(register_entries), len(g17p.REGISTER_FLAG_ONLY_SLOTS)))

    # The hardware-data object names two regions of its own.
    region_records = []
    for index, record in enumerate(g17p.HWDATA_REGION_RECORDS):
        addr, _ = arena.alloc_at(
            hwdata_va + g17p.NATIVE_HWDATA_REGION_OFFSETS[index],
            PAGE, "hwdata_region_%d" % index)
        region_records.append(dict(record, addr=addr))

    arena.write(hwdata_pa, build.build_hwdata(register_entries,
                                              g17p.REGISTER_FLAG_ONLY_SLOTS,
                                              g17p.PERF_TABLES,
                                              chip_id=g17p.CHIP_ID,
                                              region_records=region_records))
    for offset, data in g17p.HWDATA_BUNDLE_STATIC_RUNS:
        arena.write(hwdata_pa + offset, data)
    # The primary main object's five bare addresses are views into this same allocation, not
    # separately allocated objects. Overlay each view's populated runs while preserving the
    # hardware-data bytes beneath the first two and the overlap between the last two.
    for view_offset, valid_size, spec in zip(
            g17p.MAIN_ADDR_OBJECT_OFFSETS,
            g17p.MAIN_ADDR_OBJECT_VALID_SIZES,
            g17p.MAIN_ADDR_OBJECTS):
        for offset, data in spec["runs"]:
            # Older captures read physically past the end of unaligned views. Only bytes inside
            # the view's actual virtual-page extent are valid.
            if offset + len(data) > valid_size:
                continue
            arena.write(hwdata_pa + view_offset + offset, data)

    # The two roots sit a fixed distance apart, on that distance: the secondary's initialisation
    # message is the primary's address plus the delta in the same field, and every observed pair is
    # aligned to it. An unaligned primary leaves the secondary unable to translate its own root.
    roots_va = kern_va_base + g17p.NATIVE_ROOT_OFFSET
    root_pages = [
        arena.alloc_at(roots_va + slot * g17p.SECONDARY_ROOT_DELTA,
                       PAGE, "root%d" % slot)
        for slot in range(count)
    ]
    arena.va = roots_va + 3 * g17p.SECONDARY_ROOT_DELTA

    # Both instances are handed the same data region and the same leading region. Giving the second
    # instance private copies is a difference from what a working host does.
    region_c_va, region_c_pa = arena.alloc_at(
        roots_va - g17p.SECONDARY_ROOT_DELTA, build.REGION_C_SIZE, "region_c")
    region_a_va, region_a_pa = arena.alloc_at(
        roots_va + 2 * g17p.SECONDARY_ROOT_DELTA, PAGE, "region_a")
    arena.write(region_c_pa, build.build_region_c())

    instances = []
    primary_region_pages = {}
    primary_addr_array = None
    for slot, name in enumerate(g17p.COPROCESSOR_NAMES[:count]):
        offset = (g17p.NATIVE_PRIMARY_MAIN_OFFSET if slot == 0
                  else g17p.NATIVE_SECONDARY_MAIN_OFFSET)
        main_va, main_pa = hwdata_va + offset, hwdata_pa + offset
        print("  %-16s va %#018x  pa %#014x  %#x bytes (shared cluster)"
              % ("%s_main" % name, main_va, main_pa, build.MAIN_SIZE))

        if slot == 0:
            state_va = kern_va_base + g17p.NATIVE_PRIMARY_WORK_STATE_OFFSET
            status_a_va = kern_va_base + g17p.NATIVE_PRIMARY_STATUS_A_OFFSET
            status_b_va = state_va + g17p.NATIVE_STATUS_B_OFFSET
        else:
            state_va = kern_va_base + g17p.NATIVE_SECONDARY_WORK_STATE_OFFSET
            status_a_va = kern_va_base + g17p.NATIVE_SECONDARY_STATUS_A_OFFSET
            status_b_va = 0
        state_pa = private_cluster_pa + (state_va - private_cluster_va)
        status_a_pa = private_cluster_pa + (status_a_va - private_cluster_va)
        status_b_pa = (private_cluster_pa + status_b_va - private_cluster_va
                       if status_b_va else None)
        tail_va = status_a_va

        ring_va = hwdata_va + min(g17p.NATIVE_WORK_RING_OFFSETS)
        ring_pa = hwdata_pa + min(g17p.NATIVE_WORK_RING_OFFSETS)

        def ring_for(index, main_va=main_va, status_a_va=status_a_va):
            if index < g17p.CHANNEL_TABLE_WORK_COUNT:
                return hwdata_va + g17p.NATIVE_WORK_RING_OFFSETS[index]
            if index == g17p.CHANNEL_TABLE_WORK_COUNT:
                # Device control is embedded in the main object, at exactly main + 0x4c0 on both
                # instances, where the builder places the opening opcode.
                return main_va + build.MAIN_INTERVAL
            offset = g17p.NATIVE_TRAILING_RING_OFFSETS.get(index)
            return status_a_va + offset if offset is not None else 0

        # The last two entries are not fully populated in a capture: one carries a first state
        # address and no ring, the other is entirely empty. Filling them like the rest declares two
        # channels that do not exist.
        channels = []
        channel_state_pas = []
        for index in range(build.CHANNEL_TABLE_ENTRIES):
            # The work-state table has one more entry than there are work channels: the
            # device-control channel, at index CHANNEL_TABLE_WORK_COUNT, takes its state block from
            # this table even though its ring lives inside the main configuration object. Stopping
            # this branch one short leaves that channel with a null producer, and the first write
            # to it faults on address zero.
            if index <= g17p.CHANNEL_TABLE_WORK_COUNT:
                offset = g17p.NATIVE_WORK_STATE_OFFSETS[index]
                states = [state_va + offset
                          + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                          for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
                state_pas = [state_pa + offset
                             + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                             for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
            elif index in g17p.NATIVE_TRAILING_STATE_OFFSETS:
                offsets = g17p.NATIVE_TRAILING_STATE_OFFSETS[index]
                states = [tail_va + off if off is not None else 0
                          for off in offsets]
                state_pas = [private_cluster_pa + (address - private_cluster_va)
                             if address else 0 for address in states]
            else:
                states = [0, 0, 0]
                state_pas = [0, 0, 0]
            ring = ring_for(index)
            if index == g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [states[0], 0, 0], 0
                state_pas = [state_pas[0], 0, 0]
            elif index > g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [0, 0, 0], 0
                state_pas = [0, 0, 0]
            channels.append((states, ring))
            channel_state_pas.append(state_pas)

        if slot == 0:
            # The main object's five bare addresses are fixed internal views of the hardware-data
            # bundle, not scratch or independent allocations.
            addr_array = [hwdata_va + off
                          for off in g17p.MAIN_ADDR_OBJECT_OFFSETS]
            primary_addr_array = list(addr_array)
            # This selected-root page is reached through a computed scheduler address after the
            # initial peer exchange. It has no raw pointer for a closure walker to discover.
            arena.alloc_at(kern_va_base + g17p.NATIVE_PRIMARY_COMPUTED_PAGE_OFFSET,
                           PAGE, "%s_computed_page" % name)
            region_triples = []
            for index, (region_offset, value) in enumerate(
                    g17p.NATIVE_PRIMARY_REGION_TRIPLES):
                addr = kern_va_base + region_offset
                # The first address is intentionally unresolved in the native firmware context.
                # The other two name blank shared pages.
                if index:
                    _va, pa = arena.alloc_at(
                        addr, PAGE, "%s_region_%d" % (name, index))
                    primary_region_pages[region_offset] = pa
                region_triples.append((addr, value))
            arena.write(main_pa, build.build_main_config(
                hwdata_va, repeated_va, channels, addr_array, region_triples))
        else:
            # The second instance is handed a control-only object: no work channels, no address
            # array, and region triples carrying values but no addresses. It shares the first
            # instance's hardware-data object; a private copy is what made it fault.
            addr_array = []
            region_triples = list(g17p.SECONDARY_REGION_TRIPLES)
            extra_addr = (primary_addr_array[g17p.SECONDARY_EXTRA_ADDR_OBJECT]
                          + g17p.SECONDARY_EXTRA_ADDR_OFFSET)
            arena.write(main_pa, build.build_secondary_main_config(
                hwdata_va, repeated_va, channels, region_triples, extra_addr))

        # The exact pre-init snapshot has only +0x04 set. Later serialized captures
        # also have +0x10/+0x14, after the primary has had time to acknowledge, so
        # those two fields are firmware state rather than host handoff input.
        arena.write(status_a_pa, build.build_status_block(extra=False))
        if status_b_pa is not None:
            if legacy:
                arena.write(status_b_pa, build.build_status_block())
            else:
                arena.write(status_b_pa, build.build_primary_status_b(
                    g17p.NATIVE_PRIMARY_STATUS_B_SIZE,
                    fwctl_va, fwctl_va + g17p.CONTROL_MESSAGE_SIZE,
                    g17p.NATIVE_PRIMARY_STATUS_B_CONFIG_HEADER,
                    g17p.NATIVE_PRIMARY_STATUS_B_CONFIG_OFFSET,
                    g17p.NATIVE_PRIMARY_STATUS_B_CONFIG_RUNS))

        root_va = roots_va + slot * g17p.SECONDARY_ROOT_DELTA
        root_pa = root_pages[slot][1]
        # The secondary's root carries two further addresses the primary's does not.
        secondary_extra = [0, 0]
        if slot == 1:
            secondary_extra = [
                kern_va_base + g17p.NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS[0],
                kern_va_base + g17p.NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS[1],
            ]
            if not legacy:
                secondary_extra_pa = (private_cluster_pa
                                      + secondary_extra[1] - private_cluster_va)
                arena.write(secondary_extra_pa, build.build_sparse_object(
                    0x80, g17p.NATIVE_SECONDARY_ROOT_EXTRA_1_RUNS))
        arena.write(root_pa, build.build_root(
            version=[0x04c0, 0x0396, 0xa322, 0x0c8a],
            # Every capture has region_a zero in the root. Supplying a real region makes firmware
            # follow it into a structure this script has not filled in.
            region_a=region_a_va, main_config=main_va, region_c=region_c_va,
            status_a=status_a_va, status_b=status_b_va, kind=slot,
            secondary_extra_0=secondary_extra[0],
            secondary_extra_1=secondary_extra[1]))
        instances.append({"name": name, "ring_va": ring_va, "ring_pa": ring_pa,
                          "root_va": root_va, "root_pa": root_pa,
                          "state_pa": state_pa, "state_va": state_va,
                          "channels": channels,
                          "channel_state_pas": channel_state_pas,
                          "main_va": main_va, "main_pa": main_pa,
                          "control_ring_pa": main_pa + build.MAIN_INTERVAL,
                          "status_a_pa": status_a_pa, "status_b_pa": status_b_pa,
                          "status_a_va": status_a_va,
                          "region_c_pa": region_c_pa})
        print("  %s root at va %#018x" % (name, root_va))

    # Native immutable firmware inputs are ordinary cached memory; objects the host and firmware
    # both mutate are Shared, and the root-side objects are the only data pages not marked UXN.
    uat.iomap_at(CONTEXT, hwdata_va, hwdata_pa, g17p.NATIVE_SHARED_CLUSTER_SIZE,
                 AttrIndex=MemoryAttr.Normal, AP=1)
    for record in region_records:
        region = next(entry for entry in arena.entries
                      if entry["va"] == record["addr"])
        uat.iomap_at(CONTEXT, region["va"], region["pa"], PAGE,
                     AttrIndex=MemoryAttr.Normal, AP=1)
    if not legacy:
        uat.iomap_at(CONTEXT, fwctl_va, fwctl_pa, PAGE,
                     AttrIndex=MemoryAttr.Shared, AP=1, UXN=1)
    for root_page_va, root_page_pa in root_pages:
        uat.iomap_at(CONTEXT, root_page_va, root_page_pa, PAGE,
                     AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
    uat.iomap_at(CONTEXT, region_a_va, region_a_pa, PAGE,
                 AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
    uat.iomap_at(CONTEXT, region_c_va, region_c_pa & ~(PAGE - 1), PAGE,
                 AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
    # The main configuration object and the work rings are `AttrIndex 0` in a working host's
    # tables, fully cached, and they are the two structures firmware walks to find and service
    # work. The rings start part-way into a page, as the capture's do at `+0xdc0`, so the remap is
    # taken from the containing page rather than the ring address.
    for entry in instances:
        uat.iomap_at(CONTEXT, entry["main_va"] & ~(PAGE - 1),
                     entry["main_pa"] & ~(PAGE - 1), PAGE,
                     AttrIndex=MemoryAttr.Normal, AP=1)
        ring_base_va = entry["ring_va"] & ~(PAGE - 1)
        ring_base_pa = entry["ring_pa"] & ~(PAGE - 1)
        span = ((entry["ring_va"] - ring_base_va)
                + g17p.RING_STRIDE * g17p.CHANNEL_TABLE_WORK_COUNT)
        uat.iomap_at(CONTEXT, ring_base_va, ring_base_pa,
                     (span + PAGE - 1) & ~(PAGE - 1),
                     AttrIndex=MemoryAttr.Normal, AP=1)
    uat.flush_dirty()
    uat.invalidate_cache()
    print("  applied the native object memory attributes, including the main object "
          "and the work rings as Normal")

    # The hardware-data object's state pointer names a place, not just a page: a fixed distance
    # above the second instance's device-control state block. A standalone page satisfies the
    # pointer but not the relation, and firmware faults inside the path that selects this object.
    control_state = instances[-1]["channels"][g17p.CHANNEL_TABLE_WORK_COUNT][0][0]
    placed = control_state + g17p.HWDATA_STATE_AFTER_CONTROL_STATE
    arena.write(hwdata_pa + g17p.HWDATA_BUNDLE_STATE_PTR,
                struct.pack("<Q", placed))
    print("  state object placed at %#x, the secondary control state %#x plus %#x"
          % (placed, control_state, g17p.HWDATA_STATE_AFTER_CONTROL_STATE))

    primary_region_aliases = ({} if legacy else {
        low: (primary_region_pages[high_offset], PAGE)
        for high_offset, low in g17p.NATIVE_PRIMARY_REGION_ALIASES
    })

    return {"instances": instances, "hwdata_va": hwdata_va,
            "hwdata_pa": hwdata_pa, "region_a_va": region_a_va,
            "region_c_va": region_c_va,
            "private_cluster_va": private_cluster_va, "roots_va": roots_va,
            "fwctl_va": fwctl_va, "fwctl_pa": fwctl_pa,
            "primary_region_aliases": primary_region_aliases,
            "register_windows": len(register_entries)}


CONTROL_20_COUNT = [0x28]


def build_control_20_entry():
    """The device-control entry that registers the shared control object.

    Byte-identical to the one a working world's ring holds, checked offline. Its `+0x14` names the
    shared control object, its `+0x1c` the operand table and its `+0x24` the slot in that table.
    """
    entry = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<I", entry, 0x00, 0x20)
    struct.pack_into("<I", entry, 0x04, 1)
    struct.pack_into("<I", entry, 0x08, 0x3f)
    struct.pack_into("<Q", entry, 0x14, SHARED_CONTROL_ADDRESS)
    struct.pack_into("<Q", entry, 0x1c, CONTROL_OPERAND_TABLE_VA)
    struct.pack_into("<Q", entry, 0x24,
                     CONTROL_OPERAND_TABLE_VA + CONTROL_OPERAND_SLOT_OFFSET)
    # The count at +0x2c is how much of the command list firmware executes. A working host's is
    # 0x28; making it settable bisects the list, since executing it is what crashes here.
    struct.pack_into("<I", entry, 0x2c, CONTROL_20_COUNT[0])
    struct.pack_into("<I", entry, 0x34, 1)
    return bytes(entry)


def build_control_20_entry_runtime():
    """The registration entry a host publishes between its first and second work doorbell.

    Read out of a capture's own device-control ring, against the opening's entry in the same ring.
    They differ in three fields and nothing else: a sequence word at `+0x0c` that goes from zero to
    one, the operand-table slot at `+0x24`, which moves from slot 17 to slot 22, and the command
    count at `+0x2c`, which goes from `0x28` to `0x38`.
    """
    entry = bytearray(build_control_20_entry())
    struct.pack_into("<I", entry, 0x0c, 1)
    struct.pack_into("<Q", entry, 0x24,
                     CONTROL_OPERAND_TABLE_VA + CONTROL_OPERAND_SLOT_RUNTIME)
    struct.pack_into("<I", entry, 0x2c, CONTROL_20_COUNT_RUNTIME)
    return bytes(entry)


def build_control_20_entry_compute_binding(
        sequence, slot=COMPUTE_BINDING_OPERAND_SLOT,
        count=CONTROL_20_COUNT_RUNTIME):
    """Build a type-1 registration from the native CL_0 lifecycle."""
    entry = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<III", entry, 0x00, 0x20, 1, 0x3f)
    struct.pack_into("<I", entry, 0x0c, int(sequence))
    struct.pack_into("<Q", entry, 0x14, SHARED_CONTROL_ADDRESS)
    struct.pack_into("<Q", entry, 0x1c,
                     COMPUTE_BINDING_OPERAND_TABLE_VA)
    struct.pack_into("<Q", entry, 0x24,
                     COMPUTE_BINDING_OPERAND_TABLE_VA
                     + int(slot))
    struct.pack_into("<I", entry, 0x2c, int(count))
    struct.pack_into("<I", entry, 0x34, 1)
    return bytes(entry)


def build_control_20_entry_object(
        control_class, first_object, operand_table, slot_offset, sequence,
        context_word=0, count=0x18):
    """Build a class-1/2 object registration observed before native CL_0.

    The independently named operand page is blank at publication.  All live
    inputs are therefore explicit here rather than inherited from a captured
    page image.
    """
    entry = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<III", entry, 0x00, 0x20, int(control_class), 0x3f)
    struct.pack_into("<I", entry, 0x0c, int(sequence))
    struct.pack_into("<Q", entry, 0x14, int(first_object))
    struct.pack_into("<Q", entry, 0x1c, int(operand_table))
    struct.pack_into("<Q", entry, 0x24,
                     int(operand_table) + int(slot_offset))
    struct.pack_into("<I", entry, 0x2c, int(count))
    struct.pack_into("<I", entry, 0x30, int(context_word))
    struct.pack_into("<I", entry, 0x34, 1)
    return bytes(entry)


def build_control_20_entry_class2(
        first_object, operand_table, slot_offset, sequence,
        context_word=1, count=0x18):
    """Build one class-2 support registration."""
    return build_control_20_entry_object(
        2, first_object, operand_table, slot_offset, sequence,
        context_word=context_word, count=count)


def publish_control_tick(instance, asc, counter):
    """Publish one runtime device-control entry of the kind a host publishes after the opening.

    A mid-stream capture's ring holds `0x2e` entries with climbing counters, so a host publishes
    them. This publishes one the way this record used to: ring entry written, producer bumped, and
    nothing sent. Firmware does not take those.

    That is not firmware refusing device control at runtime, which is what this docstring used to
    say and what the ABI document used to record. It is this function not announcing. A host sends a
    `0x84` for every entry it publishes, and the same entry announced is consumed immediately. Use
    ``announce_control_entry`` to ask properly; this is kept for the unannounced comparison.
    """
    channel = g17p.CHANNEL_TABLE_WORK_COUNT
    states = instance["channel_state_pas"][channel]

    def counters():
        values = []
        for pa in states[:3]:
            if not pa:
                values.append(0)
                continue
            p.dc_civac(pa, 4)
            values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    before = counters()
    producer = before[g17p.CHANNEL_STATE_PRODUCER]
    body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<II", body, 0, 0x2e, counter)
    ring = instance["control_ring_pa"] + producer * g17p.CONTROL_MESSAGE_SIZE
    iface.writemem(ring, bytes(body))
    p.dc_civac(ring, len(body))
    p.write32(states[g17p.CHANNEL_STATE_PRODUCER], producer + 1)
    p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 8)

    after = before
    deadline = time.time() + 0.05
    while time.time() < deadline:
        with contextlib.suppress(Exception):
            asc.work_pending()
        after = counters()
        if after[g17p.CHANNEL_STATE_CONSUMER] > before[g17p.CHANNEL_STATE_CONSUMER]:
            break
        time.sleep(0.001)
    taken = after[g17p.CHANNEL_STATE_CONSUMER] > before[g17p.CHANNEL_STATE_CONSUMER]
    print("  control tick %d at slot %d: %s -> %s  %s"
          % (counter, producer, list(before), list(after),
             "consumed" if taken else "not consumed"))
    return {"counter": counter, "slot": producer, "before": list(before),
            "after": list(after), "consumed": bool(taken)}


def announce_control_entry(instance, asc, body, label, payload=None):
    """Publish one device-control entry on a running instance and announce it.

    The opening sequence is staged before the descriptor goes over and firmware consumes it while
    accepting the descriptor, as a bulk read: the counters reach four and nothing the `0x20` should
    have done happens. Publishing while firmware is running, with the `0x84` announcement a host
    sends per entry, exercises the handler instead of the bulk read.
    """
    channel = g17p.CHANNEL_TABLE_WORK_COUNT
    ring_pa = instance["control_ring_pa"]
    states = instance["channel_state_pas"][channel]

    def counters():
        values = []
        for pa in states[:3]:
            if not pa:
                values.append(0)
                continue
            p.dc_civac(pa, 4)
            values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    before = counters()
    if (os.getenv("G17P_CONTROL_RING_RECYCLE") == "1"
            and before == (255, 255, 255)):
        for address in states[:3]:
            p.write32(address, 0)
            p.dc_civac(address, 4)
        u.inst("dsb sy")
        before = counters()
        if before != (0, 0, 0):
            raise RuntimeError(
                "device-control ring recycle failed: %r" % (before,))
        print("  recycled empty device-control ring to [0, 0, 0]",
              flush=True)
    producer = before[g17p.CHANNEL_STATE_PRODUCER]
    target = producer + 1
    iface.writemem(ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, body)
    p.dc_civac(ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, len(body))
    p.write32(states[g17p.CHANNEL_STATE_PRODUCER], producer + 1)
    p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 8)

    crashed = None
    after = before
    deadline = time.time() + 0.1
    while time.time() < deadline:
        try:
            asc.db.send(DoorbellMsg(
                TYPE=g17p.MSG_CONTROL_DONE,
                CHANNEL=(CONTROL_ANNOUNCE_PAYLOAD if payload is None else payload)))
            # Service at most one reply. With the next work producer already visible, firmware can
            # keep generating 0x42 events until its work doorbell; draining to an empty mailbox
            # here deadlocks the host before it can ring that doorbell.
            if asc.has_messages():
                asc.work()
        except Exception as exc:
            crashed = str(exc)
            break
        after = counters()
        if after[g17p.CHANNEL_STATE_CONSUMER] >= target:
            break
        time.sleep(0.001)
    taken = after[g17p.CHANNEL_STATE_CONSUMER] >= target
    print("  %s at slot %d: %s -> %s  %s%s"
          % (label, producer, list(before), list(after),
             "consumed" if taken else "not consumed",
             "" if crashed is None else "  (crash: %s)" % crashed))
    return {"slot": producer, "before": list(before), "after": list(after),
            "consumed": bool(taken), "crashed": crashed}


def announce_control_entries(instance, asc, bodies, label, payload=None):
    """Publish and announce a contiguous device-control batch."""
    channel = g17p.CHANNEL_TABLE_WORK_COUNT
    ring_pa = instance["control_ring_pa"]
    states = instance["channel_state_pas"][channel]

    def counters():
        values = []
        for pa in states[:3]:
            p.dc_civac(pa, 4)
            values.append(struct.unpack(
                "<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    bodies = [bytes(body) for body in bodies]
    if not bodies:
        raise ValueError("control batch must not be empty")
    if any(len(body) != g17p.CONTROL_MESSAGE_SIZE for body in bodies):
        raise ValueError("control batch contains a non-message-sized body")
    before = counters()
    producer = before[g17p.CHANNEL_STATE_PRODUCER]
    target = producer + len(bodies)
    if target > g17p.RING_SLOT_COUNT:
        raise RuntimeError(
            "control batch crosses the ring boundary: %d..%d" %
            (producer, target - 1))

    data = b"".join(bodies)
    iface.writemem(
        ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, data)
    p.dc_civac(
        ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, len(data))
    p.write32(states[g17p.CHANNEL_STATE_PRODUCER], target)
    p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 8)

    crashed = None
    after = before
    for _body in bodies:
        try:
            asc.db.send(DoorbellMsg(
                TYPE=g17p.MSG_CONTROL_DONE,
                CHANNEL=(CONTROL_ANNOUNCE_PAYLOAD
                         if payload is None else payload)))
            if asc.has_messages():
                asc.work()
        except Exception as exc:
            crashed = str(exc)
            break
    deadline = time.time() + 0.1
    while crashed is None and time.time() < deadline:
        after = counters()
        if after[g17p.CHANNEL_STATE_CONSUMER] >= target:
            break
        try:
            if asc.has_messages():
                asc.work()
        except Exception as exc:
            crashed = str(exc)
            break
        time.sleep(0.001)
    after = counters()
    consumed = after[g17p.CHANNEL_STATE_CONSUMER] >= target
    print(
        "  %s at slots %d..%d: %s -> %s  %s%s" % (
            label, producer, target - 1, list(before), list(after),
            "consumed" if consumed else "not consumed",
            "" if crashed is None else "  (crash: %s)" % crashed),
        flush=True,
    )
    return {
        "slot": producer,
        "last_slot": target - 1,
        "before": list(before),
        "after": list(after),
        "consumed": consumed,
        "crashed": crashed,
    }


def publish_final_26_6_control_lifecycle(
        instances, ascs, publish_primary=True, first_work_callback=None):
    """Publish the post-start control records observed on final macOS 26.6."""
    channel = g17p.CHANNEL_TABLE_WORK_COUNT

    def counters(entry):
        values = []
        for pa in entry["channel_state_pas"][channel][:3]:
            p.dc_civac(pa, 4)
            values.append(struct.unpack(
                "<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    before = [counters(entry) for entry in instances]
    if (publish_primary
            and before[0][g17p.CHANNEL_STATE_PRODUCER] != 1):
        raise RuntimeError(
            "final-26.6 primary control producer did not start at 1: %r" %
            (before[0],))
    if before[1][g17p.CHANNEL_STATE_PRODUCER] != 1:
        raise RuntimeError(
            "final-26.6 secondary control producer did not start at 1: %r" %
            (before[1],))

    secondary = instances[1]
    secondary_states = secondary["channel_state_pas"][channel]
    secondary_producer = before[1][g17p.CHANNEL_STATE_PRODUCER]
    secondary_target = int(os.getenv(
        "G17P_FINAL_26_6_SECONDARY_TARGET", "19"), 0)
    if secondary_target < secondary_producer:
        raise ValueError(
            "final-26.6 secondary target %#x precedes producer %#x" %
            (secondary_target, secondary_producer))
    secondary_body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<I", secondary_body, 0, 0x22)
    for _ in range(secondary_target - secondary_producer):
        ring_pa = (secondary["control_ring_pa"]
                   + secondary_producer * g17p.CONTROL_MESSAGE_SIZE)
        iface.writemem(ring_pa, bytes(secondary_body))
        p.dc_civac(ring_pa, len(secondary_body))
        secondary_producer += 1
        p.write32(secondary_states[g17p.CHANNEL_STATE_PRODUCER],
                  secondary_producer)
        p.dc_civac(secondary_states[g17p.CHANNEL_STATE_PRODUCER], 4)
        u.inst("dsb sy")

    primary_producer = before[0][g17p.CHANNEL_STATE_PRODUCER]
    if publish_primary:
        primary = instances[0]
        primary_states = primary["channel_state_pas"][channel]
        if os.getenv("G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE") == "1":
            primary_body = build_control_20_entry_object(
                1, 0xfffffc20c0828000, CONTROL_OPERAND_TABLE_VA,
                (PARTIAL_CONTROL_OPERAND_SLOT_OFFSET
                 if PARTIAL_OPENING_GRAPH else CONTROL_OPERAND_SLOT_OFFSET),
                0,
                count=(PARTIAL_CONTROL_COUNT
                       if PARTIAL_OPENING_GRAPH else 0x28))
        else:
            primary_body = build_control_20_entry()
        primary_ring_pa = (primary["control_ring_pa"]
                           + primary_producer * g17p.CONTROL_MESSAGE_SIZE)
        iface.writemem(primary_ring_pa, primary_body)
        p.dc_civac(primary_ring_pa, len(primary_body))
        primary_producer += 1
        p.write32(primary_states[g17p.CHANNEL_STATE_PRODUCER],
                  primary_producer)
        p.dc_civac(primary_states[g17p.CHANNEL_STATE_PRODUCER], 4)
        u.inst("dsb sy")

    if FINAL_26_6_PRE_0X84_AUDIT is not None:
        FINAL_26_6_PRE_0X84_AUDIT(instances, ascs)

    # A host announces the primary registration. The secondary records have no
    # corresponding per-record AP mailbox write.
    ascs[0].db.send(GpuMsg(0x0084000000000011))
    first_work = None
    callback = first_work_callback or FINAL_26_6_FIRST_WORK
    wait_for_registration = bool(PARTIAL_OPENING_GRAPH and publish_primary)
    if callback is not None and not wait_for_registration:
        first_work = callback(ascs)

    target = ((primary_producer, primary_producer, primary_producer),
              (secondary_producer, secondary_producer, secondary_producer))
    after = before
    crashed = {}
    deadline = time.monotonic() + 0.1
    while time.monotonic() < deadline:
        for index, instance in enumerate(ascs):
            if index in crashed:
                continue
            try:
                # Event 0x42 can remain continuously asserted while a valid
                # final-26.6 control retires.  work_pending() drains until the
                # mailbox is empty and therefore never returns in that state,
                # preventing both the counter deadline and crash checks from
                # running.  Service at most one message per poll.
                if instance.has_messages():
                    instance.work()
            except Exception as exc:
                crashed[index] = str(exc)
        after = [counters(entry) for entry in instances]
        if tuple(after) == target:
            break
        time.sleep(0.001)

    # A replay starts with registration already committed.  On a real cold
    # opening, making the paired work visible before opcode 0x20 retires races
    # firmware's internal queue-class setup even though the eventual memory
    # image is identical.  The clean partial profile therefore establishes a
    # strict control-completion -> work-publication order.
    if callback is not None and wait_for_registration:
        if tuple(after) != target:
            raise RuntimeError(
                "partial opening registration did not retire before work: "
                "%r != %r" % (after, target))
        first_work = callback(ascs)

    result = {
        "before": [list(values) for values in before],
        "after": [list(values) for values in after],
        "target": [list(values) for values in target],
        "retired": tuple(after) == target,
        "published_primary": bool(publish_primary),
        "first_work": first_work,
        "crashed": {instances[index]["name"]: value
                    for index, value in crashed.items()},
    }
    print("  final-26.6 post-start control lifecycle: %s -> %s  %s"
          % (result["before"], result["after"],
             "retired" if result["retired"] else "NOT RETIRED"),
          flush=True)
    return result


def apply_native_partial_opening_queue(prepared):
    """Give the staged grid-0/1 work partial's measured first ownership.

    The generic cold-boot seed describes the init-pair ownership captured by
    the older render workload.  The final-26.6 forced-partial stream reuses the
    same queue-record addresses but, before their first producers are visible,
    binds them to scheduler head zero, channel-control record zero, identity
    0x15, and the class-2/shared object at c0828000.  Apply this only at the
    final pre-producer boundary, after the control object has reached its
    native mapping.
    """
    if os.getenv("G17P_NATIVE_PARTIAL_OPENING_QUEUE") != "1":
        return False

    submission = load_backend_modules().g17p_submission
    write = prepared["write"]
    job_list = 0xfffffc2000000000
    channel_control = 0xfffffc20c07b8000
    shared_control = 0xfffffc20c0828000
    queue_uuid = 0x15
    write(job_list, g17p.build_job_list(job_list))

    for name, queue in prepared["queues"].items():
        # The clean capture's complete queue records are generated by this
        # public constructor with the scheduled-queue profile.  Replacing the
        # whole record also removes stale generic fields at +0x28..+0x48.
        record = g17p.build_queue_record(
            pointers_addr=queue.pointers_addr,
            ring_addr=queue.item_ring,
            job_list_addr=job_list,
            context_addr=channel_control,
            uuid=queue_uuid,
            priority=2,
            prio5=2,
            unk_2c=2,
            unk_38=0,
            sentinel_size=2,
        )
        write(queue.address, record)
        queue.job_list_addr = job_list
        queue.record = g17p.parse_queue_record(record)

        # Native initializes an additional ring-capacity word immediately
        # after the parsed pointer block.
        write(queue.pointers_addr + 0x60, struct.pack("<Q", 0x500))

        optional = prepared["stage_again"][name]["items"][1]
        write(optional + submission.OPTIONAL_ITEM_POINTER_OFFSETS[
            "shared_control"], struct.pack("<Q", shared_control))
        write(optional + submission.OPTIONAL_ITEM_POINTER_OFFSETS[
            "channel_control"], struct.pack("<Q", channel_control))
        # These are the complete scalar differences between the generic
        # grid-0/1 optional record and the clean first partial record.  The
        # fields at +0x46 and +0x56 deliberately remain zero.
        for offset, value in ((0x1e, 2), (0x32, 1), (0x5a, queue_uuid),
                              (0x5e, 2)):
            write(optional + offset, struct.pack("<H", value))

        # The native event counter is 0x102 for both halves of this first
        # group; the generic group-one record contains 0x100.
        event = prepared["stage_again"][name]["items"][2]
        write(event + g17p.EVENT_RECORD_COUNTER,
              struct.pack("<I", 0x102))

    u.inst("dsb sy")
    print(
        "  native partial cold-boot opening binds job list %#x, shared %#x, "
        "channel control %#x, UUID %#x" % (
            job_list, shared_control, channel_control, queue_uuid),
        flush=True,
    )
    return True


def graft_blank_initdata(arena, capture, built, instances, wanted):
    """Fill every initdata byte this path leaves zero with the capture's own.

    The submission graph is byte-exact but the initdata graph is not, and it is the surface a replay
    covers by restoring it. Measured offline against the capture: the two roots are identical, the
    data region differs in 8 bytes, each status block in 6, and the hardware-data object in 342
    bytes across 173 runs, most of them recognisably clock and thermal configuration, floats and
    round decimal integers, that this path leaves zero.

    The rule is to copy only where this path's own byte is zero. That fills in what is blank without
    touching a field this path deliberately set, so every address it computes for itself survives:
    a differing address has a non-zero byte on both sides and is left alone.

    The work rings and both main configuration objects are excluded. Their content is this path's
    to publish, and the capture's rings hold that world's own work items in slots this path does
    not use.
    """
    hwdata_va = built["hwdata_va"]
    excluded = []
    for offset in (g17p.NATIVE_PRIMARY_MAIN_OFFSET,
                   g17p.NATIVE_SECONDARY_MAIN_OFFSET):
        excluded.append((hwdata_va + offset, build.MAIN_SIZE))
    for offset in g17p.NATIVE_WORK_RING_OFFSETS:
        excluded.append((hwdata_va + offset, g17p.RING_STRIDE))

    candidates = [("hwdata", hwdata_va, g17p.NATIVE_SHARED_CLUSTER_SIZE),
                  ("data_region", built["region_c_va"], build.REGION_C_SIZE)]
    for entry in instances:
        candidates.append(("status_a", entry["status_a_va"],
                           build.STATUS_BLOCK_SIZE))
    if "private" in wanted:
        # The private cluster is 1.5 MiB this path allocates as zeros and writes nothing into but
        # the status blocks, where a working host has 8,197 bytes: the largest single block of
        # missing input left, and the record describes it as thermal and performance configuration.
        #
        # Its channel state blocks are excluded. Those are counters this path owns, and a captured
        # consumer index says work was taken when none has been.
        for entry in instances:
            for states in entry["channels"]:
                for address in states[0]:
                    if address:
                        excluded.append((address, 8))
            excluded.append((entry["status_a_va"], build.STATUS_BLOCK_SIZE))
        candidates.append(("private", built["private_cluster_va"],
                           g17p.NATIVE_PRIVATE_CLUSTER_SIZE))
    if "computed" in wanted:
        # Three small pages the main configuration object names that this path allocates blank. The
        # first is reached through a computed scheduler address rather than any raw pointer, so no
        # closure walk finds it, and the scheduler is where the cache-maintenance fault on a null
        # happens. Together they are 32 bytes of the remaining gap.
        for name in ("primary_computed_page", "primary_region_1",
                     "primary_region_2"):
            record = next((entry for entry in arena.entries
                           if entry["name"] == name), None)
            if record is not None:
                candidates.append(("computed", record["va"], record["size"]))

    regions = [record for record in candidates if record[0] in wanted]

    print("Grafting the initdata fields this path leaves blank: %s"
          % (", ".join(sorted(wanted)) if wanted else "nothing"))
    total = 0
    for name, base, size in regions:
        pa = arena.physical(base)
        if pa is None:
            print("  %-22s %#x is not in the arena, skipped" % (name, base))
            continue
        theirs = capture.bytes_or_zero(base, size)
        p.dc_civac(pa, size)
        ours = bytearray(iface.readmem(pa, size))
        filled = 0
        for index in range(size):
            if ours[index] or not theirs[index]:
                continue
            address = base + index
            if any(start <= address < start + span for start, span in excluded):
                continue
            ours[index] = theirs[index]
            filled += 1
        if filled:
            iface.writemem(pa, bytes(ours))
            p.dc_civac(pa, size)
            audit_capture_write("initdata-graft:%s" % name, base, filled)
        total += filled
        print("  %-22s %#08x bytes, filled %d" % (name, size, filled))
    print("  %d bytes copied from the capture in total" % total)
    return {"bytes": total}


def stage_device_control(arena, capture, instances, opening="perform",
                         prefill_operand=False):
    """Put both instances' opening sequences in their rings before the descriptor goes over.

    A working host has its first device-control entry in the ring, with the producer already
    advanced, before it hands over the descriptor. Staging afterwards is what this path used to do,
    and firmware then never scans the channel: the ring is read as part of accepting the
    descriptor, not in response to the later notification.
    """
    print("Staging the device-control opening sequences")
    final_26_6_lifecycle = (
        os.getenv("G17P_FINAL_26_6_CONTROL_LIFECYCLE") == "1")
    final_26_6_secondary = (
        os.getenv("G17P_FINAL_26_6_SECONDARY_LIFECYCLE") == "1")
    # The `0x20` entry's operand table. Left empty by default, since the slot is firmware's to fill
    # and the capture's own table is entirely zero.
    table = None
    operand_entries = (
        PARTIAL_CONTROL_OPERAND_ENTRIES if PARTIAL_OPENING_GRAPH else
        (CONTROL_OPERAND_ENTRIES_RUNTIME
         if CONTROL_OPERAND_RUNTIME[0] else CONTROL_OPERAND_ENTRIES)
    )
    if PARTIAL_OPENING_GRAPH:
        # Native's opening control sees the initial zero page.  The host
        # publishes the complete 28-entry render-root table only in the
        # following control-0x84 -> work-0x83 interval.  Prefilling it here
        # makes firmware allocate five extra buffers, inflates the dispatch
        # bounds, and leaves the later partial store without native state.
        print("  clean partial operand table left zero through opcode 0x20",
              flush=True)
    elif prefill_operand and not final_26_6_lifecycle:
        table = g17p_submission.build_partial_operand_table(
            CONTROL_OPERAND_BUFFER_BASE, operand_entries)
        print("  operand table filled: %d entries on the %#x stride, buffers from %#x "
              "on the %#x stride"
              % (operand_entries, CONTROL_OPERAND_ENTRY_STRIDE,
                 CONTROL_OPERAND_BUFFER_BASE, CONTROL_OPERAND_BUFFER_STRIDE))
    elif final_26_6_lifecycle:
        print("  operand table left zero for the final-26.6 opening 0x20")
    render_flags = lambda address: capture.flags_for_root(
        RENDER_SNAPSHOT_ROOT, address, LOW_ALIAS_FLAGS
    )
    arena.alloc_at(CONTROL_OPERAND_TABLE_VA, PAGE, "control_operand_table",
                   data=table, flags=render_flags(CONTROL_OPERAND_TABLE_VA))
    arena.alloc_at(
        COMPUTE_BINDING_OPERAND_TABLE_VA, PAGE,
        "compute_binding_operand_table",
        flags=render_flags(CONTROL_OPERAND_TABLE_VA),
    )
    arena.alloc_at(
        COMPUTE_CLASS2_SUPPORT_TABLE_VA, PAGE,
        "compute_class2_support_table",
        flags=render_flags(CONTROL_OPERAND_TABLE_VA),
    )
    for index in range(CONTROL_OPERAND_ENTRIES,
                       CONTROL_OPERAND_ENTRIES_RUNTIME):
        va = CONTROL_OPERAND_BUFFER_BASE + index * CONTROL_OPERAND_BUFFER_STRIDE
        arena.alloc_at(
            va, CONTROL_OPERAND_BUFFER_SIZE,
            "runtime_operand_buffer_%d" % index,
            flags=render_flags(
                CONTROL_OPERAND_BUFFER_BASE
                + (CONTROL_OPERAND_ENTRIES - 1) * CONTROL_OPERAND_BUFFER_STRIDE
            ),
        )

    present_primary_done = (
        os.getenv("G17P_SOURCE_PRESENT_PRIMARY_CONTROL_DONE") == "1")
    staged = []
    for slot, entry in enumerate(instances):
        if final_26_6_lifecycle and slot == 0 and present_primary_done:
            init_body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<I", init_body, 0,
                             g17p.CONTROL_MESSAGE_INIT)
            control_body = build_control_20_entry_object(
                1, 0xfffffc20c0828000, CONTROL_OPERAND_TABLE_VA,
                (PARTIAL_CONTROL_OPERAND_SLOT_OFFSET
                 if PARTIAL_OPENING_GRAPH else CONTROL_OPERAND_SLOT_OFFSET),
                0,
                count=(PARTIAL_CONTROL_COUNT
                       if PARTIAL_OPENING_GRAPH else 0x28))
            body = bytes(init_body) + control_body
            produced = 2
            described = (
                "one final-26.6 opening opcode %#x and one source-built "
                "consumed class-1 0x20" % g17p.CONTROL_MESSAGE_INIT)
        elif final_26_6_lifecycle or (final_26_6_secondary and slot == 1):
            opcode = (g17p.CONTROL_MESSAGE_INIT if slot == 0 else 0x2a)
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<I", body, 0, opcode)
            body = bytes(body)
            produced = 1
            described = "one final-26.6 opening opcode %#x" % opcode
        elif slot == 0:
            init_count = (1 if os.getenv("G17P_NATIVE_CONTROL_PREFIX") == "1"
                          else 3)
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE * init_count)
            for index in range(init_count):
                struct.pack_into("<I", body, index * g17p.CONTROL_MESSAGE_SIZE,
                                 g17p.CONTROL_MESSAGE_INIT)
            body = bytes(body) + build_control_20_entry()
            produced = init_count + 1
            described = ("%d x %#x then one 0x20 registering the shared "
                         "control object at %#x"
                         % (init_count, g17p.CONTROL_MESSAGE_INIT,
                            SHARED_CONTROL_ADDRESS))
        else:
            produced = sum(count for _, count in SECONDARY_CONTROL_SEQUENCE)
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE * produced)
            index = 0
            for opcode, count in SECONDARY_CONTROL_SEQUENCE:
                for _ in range(count):
                    struct.pack_into("<I", body,
                                     index * g17p.CONTROL_MESSAGE_SIZE, opcode)
                    index += 1
            body = bytes(body)
            described = ", ".join("%d x %#x" % (count, opcode)
                                 for opcode, count in SECONDARY_CONTROL_SEQUENCE)

        iface.writemem(entry["control_ring_pa"], body)
        p.dc_civac(entry["control_ring_pa"], len(body))
        producer_pa = entry["channel_state_pas"][
            g17p.CHANNEL_TABLE_WORK_COUNT][g17p.CHANNEL_STATE_PRODUCER]
        p.write32(producer_pa, produced)
        p.dc_civac(producer_pa, 8)
        if opening == "done":
            # Present the opening as already consumed, which is the state the only world observed to
            # render is in: its control counters read [4, 4, 4] before the initial 0x89 and its
            # firmware processes no device-control entry. Firmware here has always consumed all
            # four instead.
            for index in range(g17p.CHANNEL_STATE_PRODUCER):
                pa = entry["channel_state_pas"][
                    g17p.CHANNEL_TABLE_WORK_COUNT][index]
                if pa:
                    p.write32(pa, produced)
                    p.dc_civac(pa, 8)
        staged.append({"instance": entry["name"], "produced": produced})
        print("  staged %s control: %s, producer %d%s"
              % (entry["name"], described, produced,
                 ", presented consumed" if opening == "done" else ""))
    return staged


def prepare_final_26_6_opening_control(arena):
    """Install final 26.6's opening control object."""
    if os.getenv("G17P_FINAL_26_6_CONTROL_LIFECYCLE") != "1":
        return

    support_va = 0xfffffc20c0828000
    # The clean partial graph owns its pool-A slots at c15f8000; the control
    # object's state page remains the distinct c1600000 page named by native.
    state_va = (PARTIAL_OPENING_SHARED_CONTROL_INNER_ADDRESS
                if PARTIAL_OPENING_GRAPH
                else LEAF_PAGE_ADDRESSES["pool_a_slots"])
    support_pa = arena.physical(support_va)
    state_pa = arena.physical(state_va)
    if support_pa is None or state_pa is None:
        raise RuntimeError(
            "final-26.6 opening resource pages are not mapped: %#x/%#x" %
            (support_va, state_va))

    if PARTIAL_OPENING_GRAPH:
        # The clean native pre-kick graph already presents state byte 2.
        # Final-26.6 advances the cursor 0xc8 -> 0xe0 but, unlike the older
        # bootstrap path, does not advance this distinct state page itself.
        present_primary_done = (
            os.getenv("G17P_SOURCE_PRESENT_PRIMARY_CONTROL_DONE") == "1")
        support = g17p_compute.build_compute_compact_control_support(
            2, CONTROL_OPERAND_TABLE_VA, 0, state_va,
            active=0, resource_class=0x19,
            cursor=(PARTIAL_SHARED_CONTROL_COUNT_AFTER
                    if present_primary_done
                    else PARTIAL_SHARED_CONTROL_COUNT_BEFORE),
            final_kind=3,
            header_value=1,
        )
        profile = (
            "class-2 partial, source-presented post-control"
            if present_primary_done else "class-2 partial")
        initial_state = 2
    else:
        support = g17p_compute.build_compute_compact_control_support(
            1, CONTROL_OPERAND_TABLE_VA, 0, state_va,
            active=0, resource_class=0x11, cursor=0x88, final_kind=2,
        )
        profile = "class-1 bootstrap"
        initial_state = 1
    # Only the compact object's 0x70-byte body belongs to this mapping.
    support = support[:0x70]
    iface.writemem(support_pa, support)
    iface.writemem(state_pa, struct.pack("<I", initial_state))
    p.dc_civac(support_pa, len(support))
    p.dc_civac(state_pa, 4)
    u.inst("dsb sy")
    print(
        "  installed final-26.6 opening %s control at %#x/%#x" %
        (profile, support_va, state_va),
        flush=True,
    )


# Blocks this path still lifts out of a capture, each suppressible so it can be measured rather
# than assumed. Most were established as required before the hardware context table was corrected,
# when a submission was consumed but never reached the accelerator, so a requirement recorded then
# does not carry over on its own.
SEED_BLOCKS = ("render-extra", "render-named", "pipelines", "fw-content", "tails",
               "submission")
SUPPRESSED_SEED = set()
# Half-open device-address ranges the render context's own content is seeded in, and ranges left
# blank, for bisecting which of those pages the work actually needs. Empty includes everything.
FIRST_CHANNEL_PAIR = [0]
# The transport channel unit and a newly-created queue's local descriptor/grid
# namespace are independent.  Native's clean first partial submission travels
# through TA_2/3D_2 while its new queue records, optional items, event subtype,
# pool records, and descriptors all start at local pair zero (grids 0/1).
# None preserves the historical coupled command-line behavior for old probes.
FIRST_DESCRIPTOR_PAIR = [None]
RENDER_WRITTEN_PAGES = []
SEED_EXTRA_RANGE = [None]
ZERO_RENDER_BYTE_RANGES = []
# Hardware leave-one-out tests proved these mapped pages need no initial
# content. The control-operand page at 0x7000208000 is also capture-free, but
# is omitted because stage_device_control owns and builds that mapping.
PROVEN_UNUSED_RENDER_RANGES = (
    (0x10000004000, 0x1000000c000),
    (0x10000020000, 0x10000028000),
    # This is retained 2408x1506 surface content from the native pass. The
    # explicit 64x64 attachment targets a caller-owned page instead; leaving
    # the native surface interior fresh-zero preserves both staged and later
    # target writes.
    (0x10000640000, 0x100007f4000),
)
SEED_EXTRA_EXCEPT = list(PROVEN_UNUSED_RENDER_RANGES)
SPARSE_RENDER_EXTENT = [False]
FAST_RENDER_WITNESS = [False]
# Diagnostic controls for proving what remains in the attachment-state pages
# that the explicit constructor does not yet emit.
SEED_CONSTRUCTED_ATTACHMENTS = set()
# Pages of the submission's own objects to place blank rather than seeded, for finding which of
# their captured content the builder does not already write for itself.
SEED_SUBMISSION_EXCEPT = set()


def seeded(block):
    """Whether a capture-derived block is still being copied."""
    return block not in SUPPRESSED_SEED


def build_render_context(arena, uat, capture, original_pa=False,
                         payload_manifest=None):
    """Map the render context a verified submission draws in, and say where each page came from.

    The register programs name render-context objects and the tiler stream binds more. Fourteen
    pages, of which six are zero in the capture and are therefore correct as fresh allocations, two
    are generated here and checked against the capture before use, and six carry content this
    project cannot generate. 1,463 of those bytes are the compiled load and store pipelines, which
    is the documented gap: nothing here compiles shaders.
    """
    package = load_backend_modules()
    render = package.g17p_render
    encoder_module = package.g17p_encoder

    # The generic bootstrap recipe is the older 2408x1506 render.  The partial
    # opening hook replaces its pages and register recipe before descriptors
    # are built.  A source-topology boot constructs these temporary pages too,
    # but must not open the legacy snapshot merely to compare pages which will
    # be replaced before publication.
    source_topology = isinstance(capture, G17PSourceTopology)
    if source_topology:
        captured = {}
    else:
        captured = {
            va: capture.blob(index)
            for va, (index, _pte) in
            capture.by_root[RENDER_SNAPSHOT_ROOT].items()
        }
    parameters = render.G17PRenderParameters(**RENDER_PARAMETERS)

    # The tiler stream is generated from parameters recovered from the captured one, and the result
    # has to be the captured bytes: a stream that merely happens to be in place is not evidence
    # that this path can build one.
    stream_page = RENDER_PARAMETERS["encoder"] & ~(PAGE - 1)
    stream_offset = RENDER_PARAMETERS["encoder"] & (PAGE - 1)
    if source_topology:
        encoder_parameters = encoder_module.G17PEncoderParameters(
            context_base=RENDER_CONTEXT_BASE,
            binds=[
                encoder_module.G17PBindPair(
                    RENDER_CONTEXT_BASE + offset, control)
                for offset, control in (
                    (0x2c0, 0x700),
                    (0x58000, 0x500),
                    (0x5801c, 0x700),
                    (0x58030, 0x500),
                    (0x5804c, 0xa00),
                    (0x68900, 0x300),
                    (0x58060, 0x200),
                    (0x5806c, 0x200),
                )
            ],
            index_buffer=RENDER_CONTEXT_BASE + 0x48000,
            index_count=6,
            instance_count=1,
            base_vertex=0,
            primitive=encoder_module.PRIMITIVE_TRIANGLE,
            opcode=encoder_module.DRAW_OPCODE_INDEXED_16,
            header_flags=0x4000002e,
            header_mode=0x01000000,
            header_state=0x00066000,
            header_class=0x00000606,
            header_control=0x500,
            tail_count=1,
            tail_flags=0xc0000000,
        )
        captured_stream = None
    else:
        captured_stream = captured[stream_page][
            stream_offset:stream_offset + encoder_module.ENCODER_SIZE]
        encoder_parameters = encoder_module.parse_encoder(
            captured_stream, RENDER_CONTEXT_BASE)
    built_stream = encoder_module.build_encoder(encoder_parameters)
    if captured_stream is not None and built_stream != captured_stream:
        raise RuntimeError("generated tiler stream differs from the capture")

    # The scissor record is the render dimensions and a scale, so it is derived rather than copied,
    # and the same equality check applies.
    scissor_body = struct.pack(
        "<IIIf", RENDER_PARAMETERS["width"], RENDER_PARAMETERS["height"], 0, 1.0)
    scissor_page = RENDER_PARAMETERS["scissor_array"] & ~(PAGE - 1)
    scissor_offset = RENDER_PARAMETERS["scissor_array"] & (PAGE - 1)
    if (not source_topology and scissor_body != captured[scissor_page][
            scissor_offset:scissor_offset + len(scissor_body)]
            and not RENDER_SIZE_OVERRIDDEN[0]):
        raise RuntimeError("generated scissor record differs from the capture")

    print("Building the render context at base %#x" % RENDER_CONTEXT_BASE)
    records = []
    seeded_bytes = 0
    bodies = {}
    capture_copied_vas = set()
    for page_va, uxn, source, name in (
            RENDER_PAGES
            + tuple((va, uxn, "zero", name) for va, uxn, name in RENDER_GUARD_PAGES)):
        if source == "zero":
            body = bytes(PAGE)
        elif source == "seed":
            block = "pipelines" if name == "load_store_pipelines" else "render-named"
            if seeded(block):
                if source_topology:
                    raise RuntimeError(
                        "source topology cannot seed captured render pages")
                body = captured[page_va]
                seeded_bytes += sum(byte != 0 for byte in body)
                capture_copied_vas.add(page_va)
                audit_capture_write("render:%s" % name, page_va, PAGE)
            else:
                body = bytes(PAGE)
                source = "zero"
        elif source == "generate":
            body = bytearray(PAGE)
            if name == "tiler_stream":
                body[stream_offset:stream_offset + len(built_stream)] = built_stream
            elif name == "scissor_array":
                body[scissor_offset:scissor_offset + len(scissor_body)] = scissor_body
            elif name == "bind0":
                body = bytearray(render.build_bind0())
            elif name == "bind1_2_3_4_6_7":
                body = bytearray(render.build_bind_group())
            elif name == "bind5_and_deflake":
                body = bytearray(render.build_viewport(
                    RENDER_PARAMETERS["width"], RENDER_PARAMETERS["height"]))
            elif name == "index_buffer":
                body = bytearray(render.build_index_buffer())
            elif name == "aux_fb":
                body = bytearray(render.build_aux_fb())
            else:
                raise RuntimeError("no generator for %s" % name)
            body = bytes(body)
            if not source_topology and body != captured[page_va]:
                if not RENDER_SIZE_OVERRIDDEN[0] or name not in SIZE_DEPENDENT_PAGES:
                    raise RuntimeError(
                        "generated page %s differs from the capture" % name)
                print("    %-22s regenerated at the overridden size" % name)
        elif source == "construct":
            if name in SEED_CONSTRUCTED_ATTACHMENTS:
                if source_topology:
                    raise RuntimeError(
                        "source topology cannot seed captured attachments")
                body = captured[page_va]
                seeded_bytes += sum(byte != 0 for byte in body)
                capture_copied_vas.add(page_va)
                audit_capture_write("render:%s-control" % name, page_va, PAGE)
                source = "seed-control"
                records.append({"name": name, "va": page_va, "source": source,
                                "uxn": uxn, "body": body,
                                "nonzero": sum(byte != 0 for byte in body)})
                bodies[page_va] = body
                continue
            body = bytearray(PAGE)
            target = package.g17p_shim.G17P_RETAINED_TARGET
            if name == "shader_resource_root":
                body = bytearray(
                    package.g17p_shim.build_shader_resource_root_page())
                sites = ()
            elif name == "uniform_payload":
                body = bytearray(
                    package.g17p_shim.build_uniform_payload_page(
                        RENDER_PARAMETERS["width"], RENDER_PARAMETERS["height"]))
                sites = ()
            elif name == "color_attachment_main":
                body = bytearray(
                    package.g17p_shim.build_raw_twiddled_attachment_page(
                        page_va, target, 64, 64))
                sites = ()
            elif name == "color_attachment_external":
                sites = ((0x220, "pbe"),)
            else:
                raise RuntimeError("no constructor for %s" % name)
            for offset, kind in sites:
                words = package.g17p_shim.build_raw_twiddled_target_descriptor(
                    target, 64, 64, kind)
                struct.pack_into("<8I", body, offset, *words)
            body = bytes(body)
        else:
            raise RuntimeError("unknown render-page source %s" % source)
        if any(body):
            bodies[page_va] = body
        # The page's seeded content is kept so the witness can compare by content at the end. A
        # count of non-zero bytes cannot see a change that keeps the count, which is exactly what
        # drawing into a framebuffer looks like.
        records.append({"name": name, "va": page_va, "source": source, "uxn": uxn,
                        "body": body,
                        "nonzero": sum(byte != 0 for byte in body)})

    # Every render page the capture has content in, not only the objects the register programs name.
    # The replay path restores all of it and renders; measured against it, the 24.4 MiB run at
    # `0x10000088000` holds content before any work runs and is exactly where a first render writes.
    # Mapping that run as fresh zero pages, which is what this path did, gives the tiler an
    # uninitialised heap.
    # Every page the loop above decided about, including the ones it decided are blank. Keying off
    # `bodies` alone would let a page this path deliberately zeroed fall through to the seeding
    # below and be filled from the capture after all, which is not a blank page but a seeded one
    # wearing a blank page's label.
    if payload_manifest:
        manifest_path = pathlib.Path(payload_manifest).expanduser().resolve()
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("page_size") != PAGE:
            raise RuntimeError("caller payload manifest has an unexpected page size")
        loaded_payloads = 0
        for entry in manifest.get("entries", ()):
            address = int(entry["va"])
            if address & (PAGE - 1) or address in bodies:
                raise RuntimeError("invalid or duplicate caller payload %#x" % address)
            payload_path = manifest_path.parent / entry["path"]
            body = payload_path.read_bytes()
            if len(body) != int(entry["size"]):
                raise RuntimeError("caller payload %#x has the wrong size" % address)
            expected = entry.get("sha256")
            if expected and hashlib.sha256(body).hexdigest() != expected:
                raise RuntimeError("caller payload %#x failed its checksum" % address)
            bodies[address] = body
            records.append({"name": "payload_%x" % address, "va": address,
                            "source": "caller-payload", "uxn": 0, "body": body,
                            "nonzero": sum(byte != 0 for byte in body)})
            loaded_payloads += 1
        print("  loaded %d opaque caller payload pages from %s" %
              (loaded_payloads, manifest_path))
    decided = {record["va"] for record in records}

    extra_pages = extra_bytes = 0
    if seeded("render-extra"):
        if source_topology:
            raise RuntimeError(
                "source topology cannot seed extra captured render pages")
        skipped = 0
        for address, (index, _pte) in sorted(
                capture.by_root[RENDER_SNAPSHOT_ROOT].items()):
            if address in bodies or address in decided:
                continue
            if arena.physical(address) is not None:
                # The device-control operand table and any later builder-owned
                # low aliases win over the captured render-root view.
                skipped += 1
                continue
            body = capture.blob(index)
            if not any(body):
                continue
            if SEED_EXTRA_RANGE[0] is not None:
                low, high = SEED_EXTRA_RANGE[0]
                if not low <= address < high:
                    skipped += 1
                    continue
            if any(low <= address < high for low, high in SEED_EXTRA_EXCEPT):
                skipped += 1
                continue
            zeroed = [(low, high) for low, high in ZERO_RENDER_BYTE_RANGES
                      if low < address + PAGE and high > address]
            if zeroed:
                mutable = bytearray(body)
                for low, high in zeroed:
                    begin = max(low, address) - address
                    end = min(high, address + PAGE) - address
                    mutable[begin:end] = bytes(end - begin)
                body = bytes(mutable)
            bodies[address] = body
            capture_copied_vas.add(address)
            audit_capture_write("render-extra", address, PAGE)
            extra_pages += 1
            extra_bytes += sum(byte != 0 for byte in body)
        print("  seeding the render context's own content: %d further pages, %d non-zero bytes%s"
              % (extra_pages, extra_bytes,
                 ", %d pages left blank by the range" % skipped if skipped else ""))
    else:
        print("  render context's own content left blank, mapped but not seeded")

    mapped, heads = map_render_extent(
        arena, uat, capture, bodies, original_pa,
        required=decided, sparse=SPARSE_RENDER_EXTENT[0])
    for record in records:
        record["pa"] = mapped[record["va"]]

    print("  %d pages: %d %s, %d fresh, %d seeded (%d non-zero bytes)"
          % (len(records),
             sum(1 for r in records if r["source"] == "generate"),
             "generated" if source_topology else "generated and checked",
             sum(1 for r in records if r["source"] == "zero"),
             sum(1 for r in records if r["source"] == "seed"), seeded_bytes))
    for record in records:
        print("    %-22s %#014x  %-8s %5d non-zero%s"
              % (record["name"], record["va"], record["source"],
                 record["nonzero"], "  executable" if not record["uxn"] else ""))
    print("  capture-content audit: %d complete render pages copied" %
          len(capture_copied_vas))
    return {"parameters": parameters, "pages": records,
            "seeded_vas": set(bodies),
            "capture_copied_vas": capture_copied_vas,
            "bodies": dict(bodies),
            "extent": {"mapped": mapped, "heads": heads},
            "registers": {
                "tiling": render.build_tiling_registers(parameters),
                "fragment": render.build_fragment_registers(parameters),
            }}


def map_render_extent(arena, uat, capture, seeded, original_pa=False,
                      required=None, sparse=False):
    """Map every extent the render context has, not only the pages the programs name.

    The capture's render context is 3,618 pages in 90 contiguous runs totalling 56.5 MiB, and the
    named objects are not single pages: the tile map and heap metadata share a 34-page run, the
    scissor base a 64-page run, the depth-bias base a 48-page run, and there is a 24.4 MiB run at
    `0x10000088000` that nothing in the register programs names at all. A working first render
    writes 917 render pages, 915 of them one contiguous run inside that region, whose content the
    record established is computed rather than copied.

    So the accelerator writes into memory an order of magnitude larger than anything the named
    pages cover, and a tiler with nowhere to put its output cannot run. This maps the whole extent
    as fresh zero pages and places the caller's seeded content inside the runs, which keeps the
    captured input at 1,549 bytes rather than importing the 425 KB the whole context holds.
    """
    root = capture.by_root[RENDER_SNAPSHOT_ROOT]

    required = set(required or ())

    def uxn_of(va):
        entry = root.get(va)
        if entry is not None:
            return (entry[1] >> 54) & 1
        # Explicit caller/compiler payload pages are executable. They are not
        # constrained to the virtual ranges occupied by the older reference
        # workload whose extent supplies the compatibility mapping policy.
        return 0

    addresses = sorted(required if sparse else set(root).union(required))
    if not addresses:
        raise RuntimeError("render extent has no pages")
    missing_root = set(addresses).difference(root)
    missing_payload = missing_root.difference(seeded)
    if missing_payload and not PARTIAL_OPENING_GRAPH:
        raise RuntimeError(
            "render pages absent from both reference map and caller payload: %s" %
            ["%#x" % address for address in sorted(missing_payload)])
    if missing_payload:
        print(
            "  allocating %d temporary generic-bootstrap pages outside the "
            "clean partial extent: %s" % (
                len(missing_payload),
                ", ".join("%#x" % address
                          for address in sorted(missing_payload)),
            ),
            flush=True,
        )
    mapped = {}
    pending = []
    for address in addresses:
        pa = arena.physical(address)
        if pa is None:
            pending.append(address)
        else:
            mapped[address] = pa
            body = seeded.get(address)
            if body is not None:
                iface.writemem(pa, body)
                p.dc_civac(pa, PAGE)

    runs = []
    if pending:
        begin = previous = pending[0]
    for address in pending[1:]:
        contiguous = address == previous + PAGE and uxn_of(address) == uxn_of(begin)
        if contiguous and original_pa:
            # With original addresses a run also has to be contiguous physically, since the whole
            # run is mapped from one base.
            here = capture.pas.get(address)
            there = capture.pas.get(previous)
            contiguous = (here is not None and there is not None
                          and here == there + PAGE)
        if contiguous:
            previous = address
            continue
        runs.append((begin, previous + PAGE, uxn_of(begin)))
        begin = previous = address
    if pending:
        runs.append((begin, previous + PAGE, uxn_of(begin)))

    print("Mapping the render context's %s extent: %d pages in %d runs, %.1f MiB"
          % ("explicit" if sparse else "full", len(addresses), len(runs),
             len(addresses) * PAGE / float(1 << 20)))
    for begin, end, uxn in runs:
        span = end - begin
        if original_pa:
            pa = capture.pas.get(begin)
            if pa is None:
                pa = u.memalign(PAGE, span)
        else:
            pa = u.memalign(PAGE, span)
        # Zeroed on the target rather than by transferring 56 MiB over the proxy.
        p.memset32(pa, 0, span)
        for offset in range(begin, end, PAGE):
            body = seeded.get(offset)
            if body is not None:
                iface.writemem(pa + (offset - begin), body)
        p.dc_civac(pa, span)
        uat.iomap_at(CONTEXT, begin, pa, span, UXN=uxn, **RENDER_PAGE_FLAGS)
        for offset in range(begin, end, PAGE):
            mapped[offset] = pa + (offset - begin)
        arena.entries.append({"name": "render_extent_%#x" % begin, "va": begin,
                              "pa": pa, "size": span})
    uat.flush_dirty()
    if len(mapped) != len(addresses):
        raise RuntimeError("render extent mapped %d of %d pages" %
                           (len(mapped), len(addresses)))

    # A head sample of every mapped page, so a scan afterwards can say whether anything in the
    # whole extent changed rather than only whether the fourteen named pages did. The large region
    # a first render writes takes the same 32 bytes in every `0x400` block, so a page's head
    # catches it.
    heads = {}
    sampled_addresses = (sorted(required) if FAST_RENDER_WITNESS[0]
                         else sorted(mapped))
    for address in sampled_addresses:
        pa = mapped[address]
        p.dc_civac(pa, PAGE)
        heads[address] = bytes(iface.readmem(pa, 32))
    print("  sampled the head of %d/%d mapped render pages%s" % (
        len(heads), len(mapped),
        " (fast witness)" if FAST_RENDER_WITNESS[0] else ""))

    # The accelerator walks these, and a page that translates for the host but not through the
    # context the work names would look exactly like this: work retired, nothing drawn.
    checked = failures = 0
    for address in sorted(mapped)[::37]:
        resolved = uat.iotranslate(CONTEXT, address, 8)
        checked += 1
        if not resolved or resolved[0][0] != mapped[address]:
            failures += 1
            print("  %#x resolves to %s, not the %#x it was mapped at"
                  % (address,
                     "nothing" if not resolved else "%#x" % (resolved[0][0] or 0),
                     mapped[address]))
    print("  translation check: %d sampled, %d wrong" % (checked, failures))
    if failures:
        raise RuntimeError("%d render mappings do not resolve" % failures)

    missing = sorted(set(seeded) - set(mapped))
    if missing:
        raise RuntimeError("seeded pages outside every run: %s"
                           % ["%#x" % address for address in missing])
    return mapped, heads


def build_context_queue_state(arena, uat, capture, phase="before"):
    """Build the four objects a first-work optional item names.

    ``phase`` selects whether the shared control object is presented before its first `0x20` or
    after. The replay path renders from a world where it is already after: its control counters are
    restored past the opening, so its firmware processes no device-control entry at all and the
    bound state comes entirely from memory. Presenting the after state is therefore what copying
    that world means, as opposed to performing the binding and having firmware advance it.

    The generic fixture maps each kind's context object through low and
    firmware aliases.  The clean partial-opening graph gives the two views
    distinct physical backing, but publishes identical generated contents in
    both.  The first pages' descriptor and queue addresses are written later,
    once those objects exist; later pages provide item slots as the queue
    grows.
    """
    def alloc_page():
        pa = u.memalign(PAGE, PAGE)
        p.memset32(pa, 0, PAGE)
        p.dc_civac(pa, PAGE)
        return pa

    print("Building the context and queue state the optional items name")
    state = {"pages": {}}
    for kind in ("tiling", "fragment"):
        pas = [alloc_page() for _ in range(INITIAL_QUEUE_CONTEXT_PAGES)]
        low_pas = ([alloc_page() for _ in range(INITIAL_QUEUE_CONTEXT_PAGES)]
                   if PARTIAL_OPENING_GRAPH else pas)
        pa = pas[0]
        body = bytearray(PAGE)
        for offset, value in CONTEXT_QUEUE_WORDS[kind]:
            struct.pack_into("<Q", body, offset, value)
        iface.writemem(pa, bytes(body))
        p.dc_civac(pa, PAGE)
        if low_pas is not pas:
            iface.writemem(low_pas[0], bytes(body))
            p.dc_civac(low_pas[0], PAGE)

        high_va = CONTEXT_QUEUE_ADDRESSES[kind]["high"]
        low_va = CONTEXT_QUEUE_ADDRESSES[kind]["low"]
        for index, page_pa in enumerate(pas):
            for va, alias_pa in ((high_va, page_pa),
                                 (low_va, low_pas[index])):
                page_va = va + index * PAGE
                flags = capture.flags_for_root(
                    RENDER_SNAPSHOT_ROOT, page_va,
                    LOW_ALIAS_FLAGS if va == low_va
                    else {"AttrIndex": MemoryAttr.Shared, "AP": 1},
                )
                uat.iomap_at(CONTEXT, page_va, alias_pa, PAGE, **flags)
                arena.entries.append({
                    "name": "context_queue_%s_%s_%d" % (
                        kind, "high" if va == high_va else "low", index),
                    "va": page_va, "pa": alias_pa, "size": PAGE,
                })
        state["pages"][kind] = {
            "pa": pa, "pas": pas, "low_pas": low_pas,
            "high": high_va, "low": low_va,
        }
        print("  %-8s context/queue object at %#x and %#x, %d pages%s"
              % (kind, low_va, high_va, len(pas),
                 ", distinct populated low backing" if low_pas is not pas else ""))

    if PARTIAL_OPENING_GRAPH:
        # The partial's optional records and descriptor tails name the same
        # compact object its device-control 0x20 binds.  It is installed at the
        # final pre-init boundary, after the surrounding graph is mapped.
        shared_control_address = PARTIAL_OPENING_SHARED_CONTROL_ADDRESS
        print("  partial shared control will be installed at %#x naming %#x"
              % (shared_control_address,
                 PARTIAL_OPENING_SHARED_CONTROL_INNER_ADDRESS))
    else:
        # The cursor and the inner byte are independent, and firmware treats them differently:
        # it adds 0x28 to the cursor for each `0x20` it processes, so a host builds 0x88 and a
        # bound world reads 0xb0.  The generic bootstrap fixture retains that historical object.
        inner_pa = alloc_page()
        iface.writemem(inner_pa, struct.pack(
            "<Q", SHARED_CONTROL_INNER_AFTER if phase in ("after", "mixed")
            else SHARED_CONTROL_INNER_BEFORE))
        p.dc_civac(inner_pa, PAGE)
        uat.iomap_at(CONTEXT, SHARED_CONTROL_INNER_ADDRESS, inner_pa, PAGE,
                     **capture.flags(
                         SHARED_CONTROL_INNER_ADDRESS,
                         {"AttrIndex": MemoryAttr.Shared, "AP": 1}))
        arena.entries.append({"name": "shared_control_inner",
                              "va": SHARED_CONTROL_INNER_ADDRESS,
                              "pa": inner_pa, "size": PAGE})

        shared_pa = alloc_page()
        body = bytearray(PAGE)
        for offset, value in SHARED_CONTROL_WORDS:
            struct.pack_into("<Q", body, offset, value)
        struct.pack_into("<I", body, SHARED_CONTROL_COUNT_AT,
                         SHARED_CONTROL_COUNT_AFTER if phase == "after"
                         else SHARED_CONTROL_COUNT_BEFORE)
        struct.pack_into("<Q", body, SHARED_CONTROL_INNER_AT,
                         SHARED_CONTROL_INNER_ADDRESS)
        iface.writemem(shared_pa, bytes(body))
        p.dc_civac(shared_pa, PAGE)
        uat.iomap_at(CONTEXT, SHARED_CONTROL_ADDRESS, shared_pa, PAGE,
                     **capture.flags(
                         SHARED_CONTROL_ADDRESS, NORMAL_OBJECT_FLAGS))
        arena.entries.append({"name": "shared_control",
                              "va": SHARED_CONTROL_ADDRESS,
                              "pa": shared_pa, "size": PAGE})
        shared_control_address = SHARED_CONTROL_ADDRESS
        print("  shared control at %#x naming %#x"
              % (SHARED_CONTROL_ADDRESS, SHARED_CONTROL_INNER_ADDRESS))

    channel_pa = alloc_page()
    body = bytearray(PAGE)
    # Native initializes only the array's first record. The final-26.6 compact
    # pair overrides CHANNEL_CONTROL_ITEM_RECORD to name that record; the
    # second record stays blank through first-work publication.
    for offset, value in CHANNEL_CONTROL_WORDS:
        struct.pack_into("<Q", body, offset, value)
    iface.writemem(channel_pa, bytes(body))
    p.dc_civac(channel_pa, PAGE)
    uat.iomap_at(CONTEXT, CHANNEL_CONTROL_ADDRESS, channel_pa, PAGE,
                 **capture.flags(CHANNEL_CONTROL_ADDRESS, NORMAL_OBJECT_FLAGS))
    arena.entries.append({"name": "channel_control", "va": CHANNEL_CONTROL_ADDRESS,
                          "pa": channel_pa, "size": PAGE})
    item_va = (CHANNEL_CONTROL_ADDRESS
               + CHANNEL_CONTROL_ITEM_RECORD * CHANNEL_CONTROL_STRIDE)
    print("  channel control array at %#x, %d records, item names %#x"
          % (CHANNEL_CONTROL_ADDRESS, CHANNEL_CONTROL_RECORDS, item_va))

    state["pointers"] = {
        kind: {
            "context_scratch": state["pages"][kind]["low"],
            "firmware_scratch": state["pages"][kind]["high"],
            "shared_control": shared_control_address,
            "channel_control": item_va,
        }
        for kind in ("tiling", "fragment")
    }
    uat.flush_dirty()
    return state


def write_context_queue_addresses(state, kind, descriptor, queue):
    """Point a kind's context/queue page at the descriptor and queue this path built."""
    pages = state["pages"][kind]
    targets = {pages["pa"], pages["low_pas"][0]}
    for pa in targets:
        iface.writemem(
            pa + CONTEXT_QUEUE_DESCRIPTOR_AT, struct.pack("<Q", descriptor)
        )
        iface.writemem(pa + CONTEXT_QUEUE_QUEUE_AT, struct.pack("<Q", queue))
        p.dc_civac(pa, PAGE)
    print("  %-8s context/queue page names descriptor %#x and queue %#x"
          % (kind, descriptor, queue))


def build_descriptor_tails(arena, uat, capture, render_state, context_state):
    """Extend both work records to full size and redirect everything their tails name."""
    render_pages = {record["name"]: record for record in render_state["pages"]}

    print("Building the full-size descriptor records and redirecting their tails")
    replacement = {}
    for page_va, (role, detail) in sorted(DESCRIPTOR_TAIL_TARGETS.items()):
        if role == "render":
            replacement[page_va] = page_va
            continue
        if role == "self":
            replacement[page_va] = DESCRIPTOR_LOW_ALIAS[detail]
            continue
        if role == "shared":
            replacement[page_va] = (
                PARTIAL_OPENING_SHARED_CONTROL_ADDRESS
                if PARTIAL_OPENING_GRAPH else SHARED_CONTROL_ADDRESS)
            continue
        if role == "seed" and PARTIAL_OPENING_GRAPH:
            # This target is a page inside the source-built primary private
            # cluster.  Allocating another page at the same DVA shadows the
            # status/config object whose five pre-0x84 fields the host later
            # publishes, so the descriptor and publication observe different
            # backing.  Reuse the already-mapped private page.
            target_pa = arena.physical(page_va)
            if target_pa is None:
                raise RuntimeError(
                    "partial tail target %#x is absent from private state" %
                    page_va)
            replacement[page_va] = page_va
            print("  %-8s %#-16x -> %#x  (existing private page)"
                  % (role, page_va, page_va))
            continue

        mapped_page_va = page_va
        if role == "status":
            # An alias, so the same physical page the register program's status address names.
            target_pa = render_pages[detail]["pa"]
            if PARTIAL_OPENING_GRAPH:
                mapped_page_va = PARTIAL_OPENING_STATUS_ADDRESSES[detail]
        else:
            target_pa = u.memalign(PAGE, PAGE)
            iface.writemem(target_pa,
                           capture.page(page_va)
                           if role == "seed" and seeded("tails") else bytes(PAGE))
            p.dc_civac(target_pa, PAGE)
        uat.iomap_at(CONTEXT, mapped_page_va, target_pa, PAGE,
                     **capture.flags(mapped_page_va,
                                     {"AttrIndex": MemoryAttr.Shared, "AP": 1}))
        arena.entries.append({"name": "tail_%s_%#x" % (role, page_va),
                              "va": mapped_page_va, "pa": target_pa,
                              "size": PAGE})
        replacement[page_va] = mapped_page_va
        print("  %-8s %#-16x -> %#x%s"
              % (role, page_va, mapped_page_va,
                 "  (alias of %s)" % detail if role == "status" else ""))
    uat.flush_dirty()

    tails = {}
    copied = seeded("tails")
    for kind, layout in DESCRIPTOR_TAIL.items():
        span = layout["native"] - layout["built"]
        # Suppressed, the tail is built rather than copied: zero everywhere, with only the listed
        # addresses written in. Everything a capture holds beyond those is scalar, and this says
        # whether any of it is load-bearing.
        body = bytearray(capture.bytes(layout["captured"] + layout["built"], span)
                         if copied else span)
        if copied:
            audit_capture_write("descriptor-tail:%s" % kind,
                                layout["captured"] + layout["built"], span)
        rewritten = 0
        for offset, value in DESCRIPTOR_TAIL_POINTERS[kind]:
            page_va = value & ~(PAGE - 1)
            if page_va not in replacement:
                raise RuntimeError("%s tail pointer at +%#x names unlisted page %#x"
                                   % (kind, offset, page_va))
            here = offset - layout["built"]
            if copied and struct.unpack_from("<Q", body, here)[0] != value:
                raise RuntimeError(
                    "%s tail at +%#x holds %#x, not the listed %#x"
                    % (kind, offset, struct.unpack_from("<Q", body, here)[0], value))
            target = replacement[page_va] + (value & (PAGE - 1))
            if target != value or not copied:
                struct.pack_into("<Q", body, here, target)
                rewritten += 1
        tails[kind] = bytes(body)
        print("  %-8s tail %#x bytes, %d non-zero, %d of %d addresses %s"
              % (kind, len(body), sum(byte != 0 for byte in body),
                 rewritten, len(DESCRIPTOR_TAIL_POINTERS[kind]),
                 "written" if not copied else "rewritten"))
    return {"tails": tails, "replacement": replacement}


def map_firmware_extent(arena, uat, capture, original_pa=False):
    """Map every firmware-context page a working host has, blank where the capture has it blank.

    Measured on hardware: zeroing the captured firmware pages the descriptor cannot reach by
    following pointers crashes firmware. And those pages are almost entirely blank, 567 of them
    holding 3,196 non-zero bytes between them, so what firmware needs is that they are mapped, not
    what they contain. The same was recorded for the secondary's startup, where blank native
    mappings were required beyond the pointer closure.

    Everything this path has already placed is left alone; this fills in the rest of the shape.
    """
    source_topology = isinstance(capture, G17PSourceTopology)
    captured = capture.by_root[capture.selected_root]
    already = {}
    for record in arena.entries:
        base = record["va"] & ~(PAGE - 1)
        for offset in range(base, record["va"] + record["size"], PAGE):
            already.setdefault(offset, record["pa"] - (record["va"] - base)
                               + (offset - base))

    blank_here = sorted(page for page in already
                        if page in captured and any(capture.blob(captured[page][0])))
    if source_topology:
        print("  source topology contains no page content")
    else:
        print("  %d pages this path placed have content in the capture: %s"
              % (len(blank_here),
                 ", ".join("%#x" % page for page in blank_here)))

    todo = sorted(address for address in captured if address not in already)
    print("Filling in the firmware context's shape: %d %s pages, "
          "%d already placed, %d to map" % (
              len(captured),
              "source-described" if source_topology else "captured",
              len(captured) - len(todo), len(todo)))

    # Group by contiguity and by the captured leaf's attributes. A working host maps most of this
    # context `AttrIndex 0`, fully cached; 126 pages `AttrIndex 2`, inner non-cacheable; and six of
    # those with UXN clear. Mapping every page `AttrIndex 2` gave 494 of 626 the wrong
    # cacheability, which firmware survives and coherency with the accelerator does not.
    def attributes_of(va):
        pte = captured[va][1]
        return ((pte >> 2) & 7, (pte >> 54) & 1)

    runs = []
    if todo:
        begin = previous = todo[0]
        for address in todo[1:]:
            contiguous = (address == previous + PAGE
                          and attributes_of(address) == attributes_of(begin))
            if contiguous and arena.native_layout is not None:
                # Keep native-described spans separate from source-allocated
                # gaps, and split wherever the native backing itself is not
                # contiguous.  Arena entries and their callers assume a run's
                # physical address is linear.
                here = arena.native_layout.page(address)
                there = arena.native_layout.page(previous)
                contiguous = (
                    (here is None and there is None)
                    or (here is not None and there is not None
                        and here == there + PAGE))
            if contiguous and original_pa:
                here = capture.pas.get(address)
                there = capture.pas.get(previous)
                contiguous = (here is not None and there is not None
                              and here == there + PAGE)
            if contiguous:
                previous = address
                continue
            runs.append((begin, previous + PAGE))
            begin = previous = address
        runs.append((begin, previous + PAGE))

    placed = content = 0
    native_placed = 0
    for begin, end in runs:
        span = end - begin
        pa = None
        if arena.native_layout is not None:
            pa = arena.native_layout.span(
                begin, span, "firmware_extent_%#x" % begin)
            if pa is not None:
                native_placed += span // PAGE
                arena.native_pages += span // PAGE
        if pa is None:
            pa = capture.pas.get(begin) if original_pa else None
        if pa is None:
            pa = u.memalign(PAGE, span)
        p.memset32(pa, 0, span)
        if seeded("fw-content"):
            for address in range(begin, end, PAGE):
                body = capture.blob(captured[address][0])
                if any(body):
                    iface.writemem(pa + (address - begin), body)
                    content += sum(byte != 0 for byte in body)
                    audit_capture_write("firmware-content", address, PAGE)
        p.dc_civac(pa, span)
        attr_index, uxn = attributes_of(begin)
        uat.iomap_at(CONTEXT, begin, pa, span,
                     AttrIndex=attr_index, AP=1, UXN=uxn)
        arena.entries.append({"name": "firmware_extent_%#x" % begin, "va": begin,
                              "pa": pa, "size": span})
        placed += span // PAGE
    uat.flush_dirty()
    print("  mapped %d pages in %d runs, %d at native PAs, %d non-zero "
          "bytes of content"
          % (placed, len(runs), native_placed, content))
    return {"captured": len(captured), "already": len(captured) - len(todo),
            "mapped": placed, "runs": len(runs), "content_bytes": content}


def prepare_work_group(arena, asc, capture, root_va, render_state, context_state,
                       tail_state, place_submission=True, announce=True,
                       defer_producers=None, defer_only=None):
    """Build and stage one paired tiling/fragment group, without ringing the doorbell.

    Firmware refuses a submission naming parameter-buffer state different from the one it has
    bound, and no host structure names that binding, so it is firmware's own. On a cold boot
    nothing has been bound, and the group carries its own state.
    """
    backend = load_backend_modules().g17p_backend

    # The context/queue state, the control objects and the tails' targets all sit at the capture's
    # addresses, which lie inside the arena's bump range. Start the heap above all of them.
    if arena.va < BACKEND_HEAP_VA_BASE:
        arena.va = BACKEND_HEAP_VA_BASE
    heap = BackendArena(arena)

    def lookup(dva):
        pa = arena.physical(dva)
        return pa if pa is not None else heap.physical(dva)

    def read(dva, size):
        pa = lookup(dva)
        if pa is None:
            raise RuntimeError("no mapping for %#x" % dva)
        p.dc_civac(pa & ~(PAGE - 1), PAGE)
        return bytes(iface.readmem(pa, size))

    def write(dva, data):
        pa = lookup(dva)
        if pa is None:
            raise RuntimeError("no mapping for %#x" % dva)
        iface.writemem(pa, bytes(data))
        p.dc_civac(pa & ~(PAGE - 1), PAGE)

    print("Preparing the first work group")
    channels = backend.G17PChannels(read, root_va)
    named = [entry for entry in channels.entries if entry["name"]]
    print("  channel table: %d entries, %d named" % (len(channels.entries), len(named)))

    repeats = {}
    placed_here = []
    placed_pages = set()
    args_place_submission = [place_submission]

    def alloc(size, name="object"):
        """Place the six leaf pages where a working host keeps them, the rest in the heap.

        Work descriptors are page-aligned, as the capture has both of them. Their tails carry
        self-references at a fixed offset from the record, and the redirect reconstructs those as
        the alias page plus that offset, so a record sitting part-way into its page puts every
        self-reference short by the page offset. The tiling record was landing at +0x2c0.
        """
        for leaf, address in LEAF_PAGE_ADDRESSES.items():
            if name != "submission_" + leaf:
                continue
            high = address >= 0xfffffc20c0000000
            # These six pages are generated submission objects, so their
            # attributes belong to the object class rather than to whichever
            # object occupied the same VA in the reference snapshot.  This
            # matters across lifecycle reuse: 0xfffffc2001610000 is a
            # read-only status alias in the older render capture, but is the
            # firmware-writable shared-slot page at the native first-CL0
            # boundary.  The latter maps all four low leaves Shared/AP=1/UXN=1
            # and both high index leaves Normal/AP=1/UXN=1.
            flags = (NORMAL_OBJECT_FLAGS if high else
                     {"AttrIndex": MemoryAttr.Shared, "AP": 1})
            arena.alloc_at(address, size, name,
                           flags=flags)
            print("      %-16s %s region, %s"
                  % (leaf, "high" if high else "low",
                     "cached" if high else "inner non-cacheable"))
            return address
        target = SUBMISSION_ADDRESSES.get(name)
        if isinstance(target, tuple):
            # Both halves of the pair share a builder name; the tiling half is built first.
            seen = repeats.get(name, 0)
            repeats[name] = seen + 1
            target = target[seen] if seen < len(target) else None
        if target is not None and not args_place_submission[0]:
            target = None
        if target is not None:
            # Seed the whole span with the capture's own bytes before the builder writes the object
            # on top. Several of these sit part-way into a page, and taking the page over with a
            # fresh blank one would discard whatever the capture has around them, which the firmware
            # extent had already placed there.
            base = target & ~(PAGE - 1)
            span = ((target - base) + size + PAGE - 1) & ~(PAGE - 1)
            # Several of these share a page: both optional items, both event items, both queue
            # records, and the two item rings, whose spans overlap in part. A second alloc_at over a
            # page already placed here maps a fresh physical page and orphans whatever the first
            # object had written into it, so each page is placed exactly once and later objects are
            # written into the page already there. Placing a whole span because one of its pages is
            # new would take the shared pages with it, which is how the first ring's published item
            # addresses were being lost and then quietly restored by the capture's own copy of them.
            for offset in range(base, base + span, PAGE):
                if offset in placed_pages:
                    continue
                blank = (not seeded("submission")
                         or offset in SEED_SUBMISSION_EXCEPT)
                data = bytes(PAGE)
                if not blank:
                    data = capture.bytes_or_zero(offset, PAGE)
                    audit_capture_write("submission:%s" % name, offset, PAGE)
                arena.alloc_at(offset, PAGE, name,
                               data=data,
                               flags=capture.flags(target, NORMAL_OBJECT_FLAGS))
                if blank and seeded("submission"):
                    print("      %s page %#x placed blank, not seeded" % (name, offset))
                placed_pages.add(offset)
            placed_here.append((name, target, size))
            return target
        return heap.alloc(size, name,
                          align=PAGE if name.startswith("work_descriptor") else 0x40)

    # The channel pair selects the physical transport slots.  The descriptor
    # pair selects the namespace of a newly-created command queue and all of
    # its local records.  They commonly match in older captures, but native's
    # clean first partial render uses transport pair 2 with descriptor pair 0.
    _transport_pair = FIRST_CHANNEL_PAIR[0]
    _descriptor_pair = FIRST_DESCRIPTOR_PAIR[0]
    if _descriptor_pair is None:
        _descriptor_pair = _transport_pair
    builder = backend.G17PPairedWorkBuilder(
        alloc, write, queue_pair=_descriptor_pair)
    if PARTIAL_OPENING_GRAPH:
        builder.bind_runtime_control_page(
            PARTIAL_OPENING_SHARED_CONTROL_ADDRESS)
        builder.tiling.status_base = \
            PARTIAL_OPENING_STATUS_ADDRESSES["ta_status"]
        builder.fragment.status_base = \
            PARTIAL_OPENING_STATUS_ADDRESSES["fragment_status"]
    graph = builder.build_submission_graph(
        index_group_ranges=SUBMISSION_INDEX_GROUP_RANGES,
        shared_count=SUBMISSION_SHARED_COUNT)
    if not legacy_aug5_topology():
        submission = load_backend_modules().g17p_submission
        pool_a = graph["pools"]["pool_a"]
        pool_b = graph["pools"]["pool_b"]
        if pool_a & (PAGE - 1) == submission.ARRAY_A_STRIDE:
            predecessor_a = bytearray(submission.ARRAY_A_STRIDE)
            struct.pack_into(
                "<Q", predecessor_a, 0,
                graph["pages"]["pool_a_slots"])
            write(pool_a - submission.ARRAY_A_STRIDE, predecessor_a)
        if pool_b & (PAGE - 1) == submission.ARRAY_B_STRIDE:
            predecessor_b = bytearray(submission.ARRAY_B_STRIDE)
            struct.pack_into(
                "<I", predecessor_b, 0,
                submission.ARRAY_B_INDEX_BASE - submission.ARRAY_A_SLOT_STEP)
            struct.pack_into(
                "<I", predecessor_b, submission.ARRAY_B_CONSTANT_OFFSET,
                submission.ARRAY_B_CONSTANT)
            struct.pack_into(
                "<Q", predecessor_b, submission.ARRAY_B_SLOT_OFFSET,
                graph["pages"]["pool_b_slots"])
            struct.pack_into(
                "<I", predecessor_b, submission.ARRAY_B_CYCLE_OFFSET,
                submission.ARRAY_B_CYCLE_WRAP)
            struct.pack_into(
                "<Q", predecessor_b, submission.ARRAY_B_SHARED_OFFSET,
                graph["pages"]["shared_slots"] + submission.SHARED_SLOT_OFFSET)
            write(pool_b - submission.ARRAY_B_STRIDE, predecessor_b)
        print("  built the two bootstrap predecessor pool records", flush=True)
    else:
        print("  legacy August 5 world: predecessor pool records left blank",
              flush=True)
    print("  built its own parameter-buffer state in %d pages" % len(heap.pages))

    tiling_registers = render_state["registers"]["tiling"]
    fragment_registers = render_state["registers"]["fragment"]
    print("  register programs: %d tiling writes, %d fragment writes"
          % (len(tiling_registers), len(fragment_registers)))
    pair = builder.item(0, None, tiling_registers, fragment_registers,
                        context_state["pointers"]["tiling"],
                        context_state["pointers"]["fragment"], CONTEXT,
                        tails=tail_state["tails"],
                        queue_pair=_descriptor_pair,
                        queue_grid_pair=_descriptor_pair,
                        parameters=render_state["parameters"])

    for kind, fields in DESCRIPTOR_BODY_FIELDS.items():
        for offset, value in fields:
            write(pair[kind][0] + offset, bytes([value]))
        print("  %-8s body fields %s"
              % (kind, ", ".join("+%#x=%#x" % f for f in fields)))

    # The tails' self-references name each descriptor through a low alias, so the descriptor's own
    # pages have to be mapped there as well: same physical pages, second device address, with the
    # low region's attributes.
    low_aliases = {}
    for kind, low in DESCRIPTOR_LOW_ALIAS.items():
        descriptor = pair[kind][0]
        base = descriptor & ~(PAGE - 1)
        span = (((descriptor - base) + DESCRIPTOR_TAIL[kind]["native"])
                + PAGE - 1) & ~(PAGE - 1)
        base_pa = lookup(base)
        if base_pa is None:
            raise RuntimeError("no physical page for the %s descriptor" % kind)
        # Recorded for context 0 rather than mapped into the shared low tables. The capture has a
        # different object at this address in the render context, 5,812 non-zero bytes that are not
        # the descriptor, and mapping the descriptor here through tables every context shares
        # replaced it and gave the render context the wrong execute permission besides. The
        # descriptor's alias belongs to context 0 alone, which is where the tails' self-references
        # are read.
        low_aliases[low] = (base_pa, span)
        print("  %-8s descriptor %#x aliased at %#x, %#x bytes"
              % (kind, descriptor, low + (descriptor - base), span))
    arena.uat.flush_dirty()
    arena.uat.invalidate_cache()

    print("  TA %s" % ["%#x" % value for value in pair["tiling"]])
    print("  3D %s" % ["%#x" % value for value in pair["fragment"]])

    def ring(channel=0):
        # The channel field encodes (queue << 2) | kind. A first submission on the init pair is 0,
        # which is what a rendering run's trace holds; the census also found 0x8 mid-stream, which
        # is grid 2, the first queue of a created pair. Ringing 0 for a group staged on a created
        # pair names the wrong queue.
        asc.db.send(DoorbellMsg(TYPE=g17p.MSG_WORK_DOORBELL, CHANNEL=channel))

    submitter = backend.G17PSubmitter(read, write, ring, channels)
    submitter.deferred_producers = defer_producers
    submitter.defer_only = defer_only

    # Both queue records are adjacent in one `0xc0`-stride array, because the closure walk reaches
    # the second only by stepping `0xc0` from the first. Separate allocations leave that step
    # landing in zeroes, so the second queue is unreachable from the descriptor graph even though
    # its own channel names it.
    queue_array = alloc(2 * g17p.QUEUE_RECORD_STRIDE, "queue_record_array")
    # One low-region page holds both queues' pointer blocks, on the per-queue stride, and the job
    # list both queues share. The list is intrusive, so it names its own address.
    for base, label in ((QUEUE_POINTER_BLOCK_VA & ~(PAGE - 1), "queue_pointer_blocks"),
                        (QUEUE_JOB_LIST_VA & ~(PAGE - 1), "queue_job_list")):
        if base in placed_pages:
            continue
        data = bytes(PAGE)
        if seeded("submission"):
            data = capture.bytes_or_zero(base, PAGE)
            audit_capture_write("submission:%s" % label, base, PAGE)
        arena.alloc_at(base, PAGE, label, data=data,
                       flags=capture.flags(base,
                                           {"AttrIndex": MemoryAttr.Shared, "AP": 1}))
        placed_pages.add(base)
    shared_job_list = (0xfffffc2000000000
                       if PARTIAL_OPENING_GRAPH else QUEUE_JOB_LIST_VA)
    write(shared_job_list, g17p.build_job_list(shared_job_list))
    print("  one job list at %#x for both queues of the pair" % shared_job_list)

    staged = {}
    stage_again = {}
    created_queues = []
    queue_of = {}
    grid_of = {}
    # The grid index and the kind are both carried by the ring slot. A captured world puts the
    # first tiling channel's queue at grid index 0 and the first fragment channel's at 1, and a
    # fragment channel whose slot lacks the kind word does not accept a publication at all.
    for name, kind, grid_index in (
            ("TA_%d" % _transport_pair, "tiling", _descriptor_pair * 2),
            ("3D_%d" % _transport_pair, "fragment",
             _descriptor_pair * 2 + 1)):
        entry = channels.by_name(name)
        if entry is None:
            raise RuntimeError("channel %s is absent from the table" % name)
        queue_addr = struct.unpack("<Q", read(entry["ring_addr"] + 8, 8))[0]
        # Unused non-bootstrap channel slots in our cold initdata are not
        # guaranteed to be all zero.  Pair 2, for example, initially carries
        # 0x5c00000000 here; it is unmapped and is not a queue descriptor.
        # Only reuse a slot when its address resolves in the firmware arena.
        if not queue_addr or lookup(queue_addr) is None:
            if queue_addr:
                print("  %s ignored unmapped stale queue pointer %#x" %
                      (name, queue_addr))
            queue_pointers = (QUEUE_POINTER_BLOCK_VA
                              + len(created_queues) * QUEUE_POINTER_BLOCK_STRIDE)
            write(queue_pointers, g17p.build_queue_pointers())
            # Allocation names follow the descriptor/grid namespace, not the
            # transport channel.  The clean partial travels on TA_2/3D_2 but
            # its grid-0/1 rings are the canonical TA_0/3D_0 objects at
            # c0008000/c000a870.
            descriptor_name = ("TA_%d" if kind == "tiling" else "3D_%d") % (
                _descriptor_pair)
            item_ring = alloc(PAGE, "%s_item_ring" % descriptor_name)
            # Fixed native rings are subpage-spaced and share backing.  Their
            # pages were zeroed when placed; clear only the three host-owned
            # entries so this write never assumes adjacent DVAs have adjacent
            # physical backing.
            write(item_ring, bytes(
                3 * g17p.ITEM_RING_ENTRY_SIZE
                if PARTIAL_OPENING_GRAPH else PAGE))
            # The queue record's context object is the same object the optional items name as
            # their channel control, the channel control array's second record.
            context_object = context_state["pointers"][kind]["channel_control"]
            queue_addr = queue_array + len(created_queues) * g17p.QUEUE_RECORD_STRIDE
            write(queue_addr, g17p.build_queue_record(
                pointers_addr=queue_pointers, ring_addr=item_ring,
                job_list_addr=shared_job_list, context_addr=context_object,
                uuid=QUEUE_UUID_VALUE))
            write(entry["ring_addr"] + g17p.RING_SLOT_QUEUE_PTR,
                  struct.pack("<Q", queue_addr))
            created_queues.append({"channel": name, "queue": queue_addr,
                                   "pointers": queue_pointers, "ring": item_ring,
                                   "job_list": shared_job_list,
                                   "context": context_object})
            print("  created a %s queue at %#x (pointers %#x, ring %#x)"
                  % (name, queue_addr, queue_pointers, item_ring))
        # The page each optional item names carries its kind's descriptor and queue addresses.
        # Both exist only now, so this is where they are written.
        write_context_queue_addresses(context_state, kind, pair[kind][0], queue_addr)
        queue = backend.G17PQueue(read, queue_addr, grid_index)
        queue_of[name] = queue_addr
        grid_of[name] = grid_index
        staged[name] = submitter.stage(
            entry, queue, pair[kind], 1, slot=0, first_submit=True, kind=kind,
            announce=announce,
            event_subtype=g17p.EVENT_SUBTYPE_BASE | grid_index)
        # Everything a second group would need. This path has only ever staged once, and whether a
        # group submitted into a world firmware is already running will execute is the question the
        # goal actually asks; it cannot be asked without staging twice.
        stage_again[name] = {"entry": entry, "queue": queue, "items": pair[kind],
                             "kind": kind, "grid_index": grid_index,
                             "announce": announce}

    counters_before = {
        name: [struct.unpack("<I", read(addr, 4))[0]
               for addr in channels.by_name(name)["state_addrs"][:3]]
        for name in staged
    }
    queues = {name: backend.G17PQueue(read, queue_of[name], grid_of[name])
              for name in staged}
    indices_before = {name: queues[name].indices() for name in staged}
    # The whole pointer block, not just the four fields the parser decodes. It is 0x60 bytes and
    # firmware owns most of it, so anything it reports about a submission it declined would be here.
    blocks_before = {name: read(queues[name].pointers_addr, g17p.QUEUE_PTR_BLOCK_SIZE)
                     for name in staged}
    # What firmware writes into the objects it was handed is the only thing it volunteers about how
    # far it got, and placing the submission graph at a working host's addresses moved every object
    # out of the heap, so a report that only covered heap pages had stopped seeing any of them.
    heap_before = {}
    for va, pa, size in heap.pages:
        p.dc_civac(pa, size)
        heap_before[va] = bytes(iface.readmem(pa, size))
    watched = list(heap.pages)
    for name, target, size in placed_here:
        pa = lookup(target)
        if pa is None:
            continue
        p.dc_civac(pa & ~(PAGE - 1), (size + PAGE - 1) & ~(PAGE - 1))
        heap_before[target] = bytes(iface.readmem(pa, size))
        watched.append((target, pa, size))

    # The queue records and item rings are `AttrIndex 0` in a working host's tables and this heap
    # is mapped Shared like the rest of the arena.
    for heap_va, heap_pa, heap_size in heap.pages:
        arena.uat.iomap_at(arena.ctx, heap_va, heap_pa, heap_size,
                           **NORMAL_OBJECT_FLAGS)
    arena.uat.flush_dirty()
    arena.uat.invalidate_cache()
    print("  remapped %d heap pages as Normal, matching a working host's queue and ring leaves"
          % len(heap.pages))

    if placed_here:
        print("  placed %d submission objects at %s" % (
            len(placed_here),
            ("source-prescribed ABI addresses"
             if isinstance(capture, G17PSourceTopology)
             else "the capture's own addresses")))
        for name, target, size in placed_here:
            print("    %-26s %#014x  %#x bytes" % (name, target, size))
    print("  staged %s; doorbell deferred" % ", ".join(sorted(staged)))
    for name in sorted(staged):
        print("    %s queue indices %s" % (name, indices_before[name]))
    return {"asc": asc, "arena": arena, "capture": capture, "uat": arena.uat,
            "channels": channels, "submitter": submitter, "read": read,
            "write": write,
            "staged": staged, "counters_before": counters_before, "queues": queues,
            "indices_before": indices_before, "heap_before": heap_before,
            "created_queues": created_queues, "heap": heap, "graph": graph,
            "watched": watched, "blocks_before": blocks_before, "ring": ring,
            "stage_again": stage_again,
            "low_aliases": low_aliases,
            "names": {target: name for name, target, _size in placed_here}}


def publish_work_group(prepared, immediate_second=False):
    """Ring the doorbell and report what firmware did with the group."""
    asc = prepared["asc"]
    channels = prepared["channels"]
    read = prepared["read"]
    staged = prepared["staged"]
    counters_before = prepared["counters_before"]
    # Once, on the primary, which is what a run that renders does: its mailbox trace holds exactly
    # one 0x83 with a zero channel, where the submitter's own notify rings twice on the theory that an
    # idle firmware treats the first as a wake-up.
    if SECONDARY_CONTROL_BEFORE[0]:
        # Does the secondary service its control channel at runtime at all, or does the first
        # dispatch stop it? Publishing before any work separates the two. The opening's entries were
        # consumed while firmware accepted the descriptor, which is not a runtime notification, so
        # the secondary has never been seen to answer one.
        bare = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into("<I", bare, 0, 0x22)
        states = prepared["instances"][1]["channel_state_pas"][
            g17p.CHANNEL_TABLE_WORK_COUNT]

        def secondary_counters():
            values = []
            for pa in states[:3]:
                if not pa:
                    values.append(0)
                    continue
                p.dc_civac(pa, 8)
                values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
            return values

        for index in range(SECONDARY_CONTROL_BEFORE[0]):
            announce_control_entry(prepared["instances"][1], prepared["ascs"][1],
                                   bytes(bare),
                                   "secondary 0x22 before any work %d" % index)
        # A host sends the secondary a 0x81 and a 0x89 within the traced window and nothing else,
        # and neither a control start nor any 0x84 payload makes it scan. The one notification never
        # tried on it is the work doorbell itself, which for the primary is what makes firmware look
        # at its rings.
        for kind, message in (("0x83 work doorbell", g17p.MSG_WORK_DOORBELL),
                              ("0x84 control done", g17p.MSG_CONTROL_DONE)):
            before = secondary_counters()
            prepared["ascs"][1].db.send(DoorbellMsg(
                TYPE=message, CHANNEL=CONTROL_ANNOUNCE_PAYLOAD))
            time.sleep(0.05)
            after = secondary_counters()
            print("  secondary %s: %s -> %s  %s"
                  % (kind, before, after,
                     "consumed" if after[0] > before[0] else "not consumed"))

    if PRE_DOORBELLS[0]:
        # The limit counts dispatches rather than executions. What a dispatch is, for the purpose of
        # that count, is not established: a doorbell, or a group actually taken off a ring. Ringing
        # with nothing staged separates them. If the group published afterwards still renders, an
        # empty doorbell is free and the count is of groups.
        for _index in range(PRE_DOORBELLS[0]):
            prepared["ring"]()
            time.sleep(CONTROL_START_GAP_MS / 1000.0)
        print("  rang %d doorbells with nothing staged" % PRE_DOORBELLS[0])

    if NO_FIRST_DOORBELL[0]:
        # Does the first group run because of its doorbell, or because it is visible while firmware
        # is still working through the opening? Publishing it and never ringing separates the two,
        # and the answer decides whether a later group needs a doorbell at all or needs an opening.
        print("  no work doorbell for the first group, on purpose")
        prepared["first_work_doorbell_at"] = time.monotonic()
    elif FIRST_DOORBELL_DELAY[0]:
        # The first group executes and every later one retires. Either being early matters or being
        # first does. Delaying only this doorbell, with one group and nothing else changed, tells
        # the two apart: if a late first group still executes, lateness is not the difference.
        print("  waiting %.1f s before the first doorbell" % FIRST_DOORBELL_DELAY[0])
        time.sleep(FIRST_DOORBELL_DELAY[0])
    if not NO_FIRST_DOORBELL[0]:
        prepared["ring"]()
        prepared["first_work_doorbell_at"] = time.monotonic()
        print("  rang the work doorbell once, as a rendering run does")
    second = None
    if immediate_second:
        # Keep this at the mailbox boundary. The normal result path reads every watched object and
        # then waits another half second before staging runtime work, which can outlive an active
        # dispatch window even when the work itself is correct.
        second = submit_second_group(prepared, fast=True)

    consumed = {}
    for name in staged:
        entry = channels.by_name(name)
        after = None
        crashed = None
        deadline = time.monotonic() + 0.05
        while time.monotonic() < deadline:
            try:
                asc.work_pending()
            except Exception as exc:
                crashed = str(exc)
                break
            after = [struct.unpack("<I", read(addr, 4))[0]
                     for addr in entry["state_addrs"][:3]]
            if after[:2] != counters_before[name][:2]:
                break
            time.sleep(0.001)
        if after is None:
            after = [struct.unpack("<I", read(addr, 4))[0]
                     for addr in entry["state_addrs"][:3]]
        consumed[name] = {"before": counters_before[name], "after": after,
                          "moved": after[:2] != counters_before[name][:2],
                          "crashed": crashed}
        print("  %s counters %s -> %s  %s%s"
              % (name, counters_before[name], after,
                 "consumed" if consumed[name]["moved"] else "no movement",
                 "" if crashed is None else " (firmware crash: %s)" % crashed))

    # Completion, separately from consumption. Acceptance moves the read index on its own and says
    # nothing about the work running, so the done index is reported beside it.
    indices = {}
    for name in sorted(staged):
        before = prepared["indices_before"][name]
        after = prepared["queues"][name].indices()
        indices[name] = {"before": before, "after": after}
        print("  %s queue indices %s -> %s  %s"
              % (name, before, after,
                 "completed" if after.get("done", 0) >= after.get("write", 1)
                 and after.get("write") else "not completed"))

    # Queue retirement is not execution: refused jobs are retired from the channel and queue, then
    # linked onto a shared firmware list. A working host keeps this list empty between doorbells.
    job_lists = {}
    for name in sorted(staged):
        address = prepared["queues"][name].job_list_addr
        key = "%#x" % address
        if key in job_lists:
            continue
        parsed = g17p.parse_job_list(read(address, g17p.JOB_LIST_SIZE), address)
        job_lists[key] = parsed
        print("  job list %#014x: first %#014x last %#014x  %s"
              % (address, parsed["first"], parsed["last"],
                 "empty" if parsed["empty"] else "nonempty"))

    current_jobs = []
    body = read(PER_SUBMISSION_RECORD_VA, 2 * PER_SUBMISSION_RECORD_STRIDE)
    for index in range(2):
        words = struct.unpack_from(
            "<8Q", body, index * PER_SUBMISSION_RECORD_STRIDE)
        current_jobs.append({
            "header": words[0],
            "kind": words[1],
            "timestamps": list(words[2:6]),
            "descriptor": words[6],
            "queue": words[7],
        })
        print("  current job %d: timestamps %s"
              % (index, " ".join("%#x" % value for value in words[2:6])))

    for name in sorted(staged):
        before = prepared["blocks_before"][name]
        after = read(prepared["queues"][name].pointers_addr,
                     g17p.QUEUE_PTR_BLOCK_SIZE)
        if before == after:
            print("  %s pointer block unchanged" % name)
            continue
        runs = [i for i in range(len(before)) if before[i] != after[i]]
        print("  %s pointer block: %d bytes changed at %s"
              % (name, len(runs), ", ".join("+%#x" % i for i in runs[:16])))
        print("      before %s" % before.hex())
        print("      after  %s" % after.hex())

    # What firmware wrote into the objects it was handed. A run that reports only counters cannot
    # distinguish firmware ignoring the group from firmware working on it.
    written = {}
    for va, pa, size in prepared["watched"]:
        p.dc_civac(pa, size)
        now = bytes(iface.readmem(pa, size))
        was = prepared["heap_before"].get(va)
        if was is None or now == was:
            continue
        differing = sum(a != b for a, b in zip(was, now))
        first = next(index for index in range(len(now)) if now[index] != was[index])
        label = prepared["names"].get(va, "heap page")
        written["%#x" % va] = {"bytes": differing, "first": first, "name": label}
        print("  firmware wrote %d bytes into %s at %#x, first at +%#x"
              % (differing, label, va, first))
    if not written:
        print("  firmware wrote nothing into any of the %d objects watched"
              % len(prepared["watched"]))

    return {"pages": len(prepared["heap"].pages), "staged": sorted(staged),
            "created_queues": prepared["created_queues"], "consumed": consumed,
            "indices": indices, "job_lists": job_lists,
            "current_jobs": current_jobs, "heap_written": written,
            "graph_pages": len(prepared["graph"].get("pages", {})),
            "immediate_second": second}


def report_leaf_attributes(uat, capture, compare_pa=False):
    """Compare this path's leaf translations against the capture's, attribute by attribute.

    Content has been compared exhaustively; the translations themselves have not. The replay path
    restores a working world's own page tables, so any attribute this path sets differently is a
    difference the accelerator sees and no content comparison can find. Checked once per contiguous
    run rather than per page, since a run is mapped from one call and shares its attributes.
    """
    def leaf(va, slot):
        """Walk to the leaf and return the raw entry, or None if it does not resolve.

        Walked through the slot the capture recorded the page under, since a page can be mapped in
        more than one context with different attributes and comparing every root against one
        context's tables reports differences that are not there.
        """
        table = uat.gpu_region + slot * 16
        entry = 0
        for shift, count, cls in uat.LEVELS:
            index = (va >> shift) & (count - 1)
            raw = struct.unpack("<Q", iface.readmem(table + 8 * index, 8))[0]
            pte = cls(raw)
            if not pte.valid():
                return None
            entry = raw
            table = pte.offset()
        return entry

    # Bits that describe how the page is accessed rather than where it is.
    fields = (("AttrIndex", 2, 7), ("AP", 6, 3), ("SH", 8, 3), ("AF", 10, 1),
              ("nG", 11, 1), ("PXN", 53, 1), ("UXN", 54, 1))

    def describe(entry):
        return tuple((entry >> shift) & mask for _name, shift, mask in fields)

    print("Leaf attributes against the capture:")
    mismatched = []
    relocated = []
    checked = 0
    for root_index in sorted(capture.by_root):
        pages = capture.by_root[root_index]
        if not pages:
            continue
        addresses = sorted(pages)
        runs = []
        begin = previous = addresses[0]
        for address in addresses[1:]:
            if address == previous + PAGE:
                previous = address
                continue
            runs.append(begin)
            begin = previous = address
        runs.append(begin)
        for address in runs:
            theirs = describe(pages[address][1])
            ours_entry = leaf(address, root_index)
            checked += 1
            if ours_entry is None:
                mismatched.append((root_index, address, None, theirs))
                continue
            ours = describe(ours_entry)
            if ours != theirs:
                mismatched.append((root_index, address, ours, theirs))
            if compare_pa:
                # Where the two sets of tables actually send the address. If every sampled address
                # resolves to the same physical page with the same attributes, then this path's
                # tables are functionally the tables a working host has, and the translation
                # structures are excluded as a cause rather than merely assumed equivalent.
                want = capture.pas.get(address)
                got = ours_entry & 0x0000FFFFFFFFC000
                if want is not None and want != got:
                    relocated.append((root_index, address, got, want))
    if compare_pa:
        print("  output pages: %d of %d sampled runs resolve somewhere other than the "
              "capture's own page" % (len(relocated), checked))
        for root_index, address, got, want in relocated[:10]:
            print("    root %-2d %#014x  ours %#014x  capture %#014x"
                  % (root_index, address, got, want))
        if len(relocated) > 10:
            print("    ... %d more" % (len(relocated) - 10))
    names = [name for name, _shift, _mask in fields]
    print("  checked %d runs across %d roots, %d differ"
          % (checked, len(capture.by_root), len(mismatched)))
    for root_index, address, ours, theirs in mismatched[:24]:
        if ours is None:
            print("    root %-2d %#014x  does not resolve here" % (root_index, address))
            continue
        parts = ["%s %d/%d" % (names[i], ours[i], theirs[i])
                 for i in range(len(names)) if ours[i] != theirs[i]]
        print("    root %-2d %#014x  ours/theirs  %s"
              % (root_index, address, ", ".join(parts)))
    if len(mismatched) > 24:
        print("    ... %d more" % (len(mismatched) - 24))
    return [{"root": r, "va": a, "ours": o, "theirs": t}
            for r, a, o, t in mismatched]


def leaf_output(uat, slot, va):
    """The physical page a context's own tables translate an address to, or None."""
    table = uat.gpu_region + slot * 16
    for shift, count, cls in uat.LEVELS:
        index = (va >> shift) & (count - 1)
        raw = struct.unpack("<Q", iface.readmem(table + 8 * index, 8))[0]
        pte = cls(raw)
        if not pte.valid():
            return None
        table = pte.offset()
    return table


def separate_native_blank_pages(uat, capture):
    """Give the measured native blank root/address pairs distinct backing."""
    separated = []
    shared_pages = {}
    legacy = legacy_aug5_topology()
    address_sets = (LEGACY_AUG5_DISTINCT_BLANK_PAGES if legacy
                    else NATIVE_DISTINCT_BLANK_PAGES)
    for root_index, addresses in sorted(address_sets.items()):
        for va in addresses:
            mapping = capture.by_root.get(root_index, {}).get(va)
            if mapping is None:
                raise RuntimeError("native blank page %#x is absent from root %d"
                                   % (va, root_index))
            if any(capture.blob(mapping[0])):
                raise RuntimeError("native blank page %#x in root %d is not blank"
                                   % (va, root_index))
            previous = leaf_output(uat, root_index, va)
            if previous is None:
                raise RuntimeError("native blank page %#x does not resolve in root %d"
                                   % (va, root_index))
            # Roots 7 through 10 share one render-context backing page at each
            # DVA in native topology.  They are collectively distinct from
            # context 0, not distinct from one another.
            fresh = None if legacy else shared_pages.get(va)
            if fresh is None:
                fresh = u.memalign(PAGE, PAGE)
                p.memset32(fresh, 0, PAGE)
                if not legacy:
                    shared_pages[va] = fresh
            uat.iomap_at(root_index, va, fresh, PAGE,
                         **capture.flags_from_pte(mapping[1]))
            separated.append({
                "root": root_index,
                "va": va,
                "previous_pa": previous,
                "pa": fresh,
            })
    uat.flush_dirty()
    uat.invalidate_cache()
    u.inst("dsb sy")
    print("  gave %d measured %s blank root/address pairs distinct backing"
          % (len(separated), "legacy-August-5" if legacy else "native"))
    return separated


def apply_render_firmware_aliases(uat, aliases=None, capture=None,
                                  render_root=None, prefer_low=False,
                                  arena=None):
    """Build the measured render-low to firmware-high physical aliases."""
    applied = []
    aliases = RENDER_FIRMWARE_ALIASES if aliases is None else aliases
    default_high_flags = Capture.flags_from_pte(0x00c0000000000443)
    default_low_flags = Capture.flags_from_pte(0x00c0000000000c8b)
    for low, high in sorted(aliases.items()):
        high_flags = default_high_flags
        low_flags = default_low_flags
        if capture is not None:
            high_flags = capture.flags_for_root(
                NATIVE_FIRMWARE_SLOT, high, default_high_flags)
            low_flags = capture.flags_for_root(
                render_root, low, default_low_flags)
        canonical = low if prefer_low else high
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, canonical)
        if pa is None:
            pa = u.memalign(PAGE, PAGE)
            p.memset32(pa, 0, PAGE)
        # Install both leaves explicitly.  For the clean first-partial world
        # the low page must be canonical: its generated control contents are
        # published after this pass through render_state's retained physical
        # inventory.  Making the already-built high page canonical silently
        # sends those later writes to an orphan.
        uat.iomap_at(NATIVE_FIRMWARE_SLOT, high, pa, PAGE, **high_flags)
        uat.iomap_at(NATIVE_FIRMWARE_SLOT, low, pa, PAGE, **low_flags)
        if arena is not None:
            # Arena.physical() is the source callbacks' DVA resolver.  Record
            # the remap last so both views agree with the live page tables.
            arena.entries.append({
                "name": "render_firmware_alias_low_%x" % low,
                "va": low, "pa": pa, "size": PAGE,
            })
            arena.entries.append({
                "name": "render_firmware_alias_high_%x" % high,
                "va": high, "pa": pa, "size": PAGE,
            })
        applied.append((low, high, pa))
    uat.flush_dirty()
    uat.invalidate_cache()
    u.inst("dsb sy")
    print("  built %d measured render-low/firmware-high aliases" % len(applied))
    return applied


def dump_firmware_pages(uat, capture, out, instances, include_channel_state=False):
    """Write this path's own content for every firmware-context page, one file per address.

    For convergence from the rendering side. The replay path can overwrite a captured page with this
    content and find the subset that stops it rendering, which names a page whose content differs and
    matters. No comparison of inputs can do that, because the inputs match.

    Each page is read through the firmware context's own tables, so an address mapped differently in
    another context is not confused with this one.
    """
    out.mkdir(parents=True, exist_ok=True)
    # The private cluster is excluded. It holds the channel state blocks, whose counters are this
    # path's own bookkeeping rather than content: grafted over a rendering world they describe a
    # different point in that world's life, and the replay refuses the run outright because the
    # device-control counters no longer match what it staged.
    # Only the pages carrying channel state are held back, rather than the whole private cluster.
    # Those counters are this path's own bookkeeping and describe a different point in a world's life,
    # which the replay refuses outright; the rest of the cluster is thermal and performance
    # configuration and is content like any other.
    held = set()
    if not include_channel_state:
        for entry in instances:
            for states, _ring in entry["channels"]:
                for address in states:
                    if address:
                        held.add(address & ~(PAGE - 1))
            held.add(entry["status_a_va"] & ~(PAGE - 1))
    written = 0
    skipped = 0
    for va in sorted(capture.by_root.get(NATIVE_FIRMWARE_SLOT, {})):
        if va in held:
            skipped += 1
            continue
        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
        if pa is None:
            continue
        p.dc_civac(pa, PAGE)
        (out / ("%x.bin" % va)).write_bytes(bytes(iface.readmem(pa, PAGE)))
        written += 1
    print("Dumped %d firmware-context pages to %s, holding back %d carrying channel state"
          % (written, out, skipped))
    return written


def dump_root_pages(uat, capture, out, root_slot):
    """Write every captured leaf in one rebuilt root for offline comparison."""
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for va in sorted(capture.by_root.get(root_slot, {})):
        pa = leaf_output(uat, root_slot, va)
        if pa is None:
            continue
        p.dc_civac(pa, PAGE)
        (out / ("%x.bin" % va)).write_bytes(bytes(iface.readmem(pa, PAGE)))
        written += 1
    print("Dumped %d pages from root slot %d to %s" %
          (written, root_slot, out))
    return written


def report_input_completeness(arena, uat, capture, fill=False, fill_only=None,
                              defer=None, fill_bytes=None, blank_like_host=False,
                              blank_only=None, separate_blank=False, scan_blank=False):
    """For every object this path hands firmware, what the capture has there and what we have.

    The comparisons so far have each covered one object at a time, which is how a whole region went
    unexamined: the pages this path allocates itself are never compared against the capture unless
    someone thinks to. This walks every arena entry and reports the bytes the capture has non-zero
    where this path has zero, which is the complete missing-input list rather than a sampled one.
    """
    print("Input completeness against the capture:")
    rows = []
    for record in sorted(arena.entries, key=lambda r: r["va"]):
        size = record["size"]
        if size > 0x200000:
            # The render and firmware extents are compared by their own seeding paths, and reading
            # tens of megabytes back over the proxy would dominate the run.
            continue
        theirs = capture.bytes_or_zero(record["va"], size)
        if not any(theirs):
            continue
        p.dc_civac(record["pa"] & ~(PAGE - 1),
                   (size + PAGE - 1) & ~(PAGE - 1))
        ours = bytes(iface.readmem(record["pa"], size))
        missing = sum(1 for i in range(size) if theirs[i] and not ours[i])
        extra = sum(1 for i in range(size) if ours[i] and not theirs[i])
        differ = sum(1 for i in range(size) if ours[i] and theirs[i]
                     and ours[i] != theirs[i])
        if not (missing or extra or differ):
            continue
        rows.append({"name": record["name"], "va": record["va"], "size": size,
                     "missing": missing, "extra": extra, "differ": differ})
    # The pass above reads each arena entry linearly from its own base, which cannot see a page that
    # was remapped inside a run: the large extents report a gap that is really the witness looking at
    # the run's original backing store. Comparing per page, resolved through the mapping that is
    # actually in force, gives an exact number. Only pages the capture has content in are compared,
    # since a blank captured page cannot be missing anything.
    per_page = []
    filled = []
    unmapped = []
    two_way = []
    blank_but_ours = []
    separated = []
    deferred = [] if defer is None else defer
    for root_index in sorted(capture.by_root):
        for va, (blob, _pte) in sorted(capture.by_root[root_index].items()):
            theirs = capture.blob(blob)
            if not any(theirs):
                # A page a working host leaves entirely blank. Every comparison this path has run
                # skipped these, so a field set here where a working host has nothing has never been
                # visible to any of them.
                #
                # Off by default. Reading them means a proxy round trip for every blank page in
                # every root, thousands of them at 16 KiB each, which added about five minutes to
                # every run for a measurement that only needs making when something has changed.
                if not scan_blank:
                    continue
                pa = leaf_output(uat, root_index, va)
                if pa is None:
                    continue
                p.dc_civac(pa, PAGE)
                mine = bytes(iface.readmem(pa, PAGE))
                if not any(mine):
                    continue
                count = sum(1 for byte in mine if byte)
                if count:
                    blank_but_ours.append((root_index, va, count, mine))
                    if separate_blank and (blank_only is None or va in blank_only):
                        # Give this root its own blank page rather than zeroing the shared one. A
                        # working host has content at these addresses in context 0 and blank pages
                        # in the render roots, which needs separate backing; this path aliases one
                        # page into every root, so zeroing through a render root destroys context
                        # 0's object instead of reproducing the distinction.
                        fresh = u.memalign(PAGE, PAGE)
                        p.memset32(fresh, 0, PAGE)
                        uat.iomap_at(root_index, va, fresh, PAGE,
                                     **capture.flags_from_pte(
                                         capture.by_root[root_index][va][1]))
                        separated.append((root_index, va, pa, fresh))
                    elif blank_like_host and (blank_only is None or va in blank_only):
                        iface.writemem(pa, bytes(PAGE))
                        p.dc_civac(pa, PAGE)
                continue
            # Resolved by walking that context's own tables, not through the arena. An arena
            # lookup knows nothing about contexts, so it returns whichever object was mapped last
            # at the address and reads the wrong page for every context that differs there. That is
            # the same conflation this path had in its mappings, and it belongs out of the
            # measurement too.
            pa = leaf_output(uat, root_index, va)
            if pa is None:
                # A page the capture has content in that this world does not map at all. Skipping
                # it silently made the gap look smaller than it is: such a page is not short by a
                # few bytes, it is absent, and nothing downstream could ever read it.
                unmapped.append((root_index, va, sum(1 for b in theirs if b)))
                continue
            p.dc_civac(pa, PAGE)
            ours = bytes(iface.readmem(pa, PAGE))
            # Two-way, resolved through the mapping in force. The one-way count answers "what has
            # the capture got that we left zero", which cannot see a byte this path wrote a
            # different value into. For work items this path builds itself that is the only
            # comparison that means anything, and it had never been made.
            #
            # Counted only when the page differs at all. These loops run over every captured page,
            # about 626 of them, and at 16 KiB each that is tens of millions of Python iterations
            # per pass; skipping the pages that match takes the completeness pass from minutes to
            # seconds and changes none of its output.
            if ours == theirs:
                continue
            differ = sum(1 for i in range(PAGE)
                         if ours[i] and theirs[i] and ours[i] != theirs[i])
            extra = sum(1 for i in range(PAGE) if ours[i] and not theirs[i])
            if differ or extra:
                two_way.append((root_index, va, differ, extra))
            missing = sum(1 for i in range(PAGE) if theirs[i] and not ours[i])
            if missing:
                per_page.append((root_index, va, missing))
                if (fill or defer is not None) and (fill_only is None or va in fill_only):
                    if defer is not None:
                        deferred.append((pa, bytes(theirs), bytes(ours)))
                        continue
                    # Supply exactly the bytes the capture has where this path has zero, and
                    # nothing else. A byte this path deliberately set is non-zero on both sides
                    # and is left alone, so every address it computes for itself survives. This
                    # closes the input gap to nothing rather than to a small number.
                    patched = bytearray(ours)
                    supplied = []
                    for i in range(PAGE):
                        if fill_bytes is not None and i not in fill_bytes:
                            continue
                        if theirs[i] and not ours[i]:
                            patched[i] = theirs[i]
                            supplied.append(i)
                    # Named, so the gap can be built rather than copied. Grouped into the words they
                    # fall in, since a byte here is almost always part of a wider field.
                    if supplied:
                        words = sorted({i & ~7 for i in supplied})
                        print("    root %-2d %#014x supplies %d bytes in %d words"
                              % (root_index, va, len(supplied), len(words)))
                        for word in words[:8]:
                            print("        +%#07x  capture %s  ours %s"
                                  % (word, theirs[word:word + 8].hex(),
                                     ours[word:word + 8].hex()))
                        if len(words) > 8:
                            print("        ... %d more words" % (len(words) - 8))
                    iface.writemem(pa, bytes(patched))
                    p.dc_civac(pa, PAGE)
                    filled.append({"root": root_index, "va": va, "bytes": missing})
    per_page.sort(key=lambda row: -row[2])
    print("  per page, resolved through the mapping in force: %d pages short, %d bytes"
          % (len(per_page), sum(row[2] for row in per_page)))
    for root_index, va, missing in per_page[:12]:
        print("    root %-2d %#014x  %5d bytes the capture has and we do not"
              % (root_index, va, missing))
    if len(per_page) > 12:
        print("    ... %d more pages" % (len(per_page) - 12))
    # Does this path give each context its own page at these addresses, or one shared page? A
    # working host has content in context 0 and blank pages in the render roots, which is only
    # possible with separate backing. If they resolve to one physical page here, zeroing through a
    # render root also destroys context 0's content.
    for probe in (0x7000438000, 0x7000460000):
        seen = []
        for root_index in sorted(capture.by_root):
            pa = leaf_output(uat, root_index, probe)
            if pa is not None:
                seen.append((root_index, pa))
        if seen:
            distinct = len({pa for _, pa in seen})
            print("  %#014x resolves in %d roots to %d distinct pages: %s"
                  % (probe, len(seen), distinct,
                     " ".join("r%d=%#x" % (r, pa) for r, pa in seen[:6])))
    if separated:
        uat.flush_dirty()
        uat.invalidate_cache()
        u.inst("dsb sy")
        print("  gave %d root-and-address pairs their own blank page, as a working host has them"
              % len(separated))
    blank_but_ours.sort(key=lambda row: -row[2])
    print("  pages a working host leaves blank that this path writes into: %d, %d bytes"
          % (len(blank_but_ours), sum(row[2] for row in blank_but_ours)))
    for root_index, va, count, mine in blank_but_ours[:20]:
        first = next(i for i in range(PAGE) if mine[i])
        print("    root %-2d %#014x  %5d bytes, first at +%#06x  %s"
              % (root_index, va, count, first, mine[first & ~7:(first & ~7) + 24].hex(" ", 8)))
    if len(blank_but_ours) > 20:
        print("    ... %d more pages" % (len(blank_but_ours) - 20))
    two_way.sort(key=lambda row: -(row[2] + row[3]))
    print("  two-way, on pages the capture has content in: %d pages differ, %d bytes changed "
          "in place, %d bytes ours only"
          % (len(two_way), sum(row[2] for row in two_way),
             sum(row[3] for row in two_way)))
    for root_index, va, differ, extra in two_way[:16]:
        print("    root %-2d %#014x  %5d differ, %5d ours only"
              % (root_index, va, differ, extra))
    if len(two_way) > 16:
        print("    ... %d more pages" % (len(two_way) - 16))
    unmapped.sort(key=lambda row: -row[2])
    print("  pages the capture has content in that this world does not map: %d, %d bytes"
          % (len(unmapped), sum(row[2] for row in unmapped)))
    for root_index, va, count in unmapped[:16]:
        print("    root %-2d %#014x  %5d bytes, unmapped here" % (root_index, va, count))
    if len(unmapped) > 16:
        print("    ... %d more pages" % (len(unmapped) - 16))
    if fill:
        u.inst("dsb sy")
        print("  filled %d bytes across %d pages, so the input gap is now nothing"
              % (sum(row["bytes"] for row in filled), len(filled)))

    rows.sort(key=lambda row: -row["missing"])
    for row in rows[:28]:
        print("  %-34s %#014x  %#08x bytes: %5d the capture has and we do not, "
              "%5d ours only, %5d both differ"
              % (row["name"], row["va"], row["size"], row["missing"],
                 row["extra"], row["differ"]))
    if len(rows) > 28:
        print("  ... %d more objects" % (len(rows) - 28))
    print("  total: %d bytes the capture has that this path leaves zero"
          % sum(row["missing"] for row in rows))
    return rows


def apply_deferred_fill(deferred):
    """Write the short bytes now rather than before the control start.

    Firmware crashes at the control start whenever these bytes are present beforehand, so it reads
    what they name at that point. Writing them after it has read gives the work the content without
    putting it in front of whatever the control start does with it.
    """
    total = 0
    for pa, theirs, ours in deferred:
        patched = bytearray(ours)
        for i in range(len(patched)):
            if theirs[i] and not ours[i]:
                patched[i] = theirs[i]
                total += 1
        iface.writemem(pa, bytes(patched))
        p.dc_civac(pa, len(patched))
    u.inst("dsb sy")
    print("Filled %d short bytes across %d pages, after the control start"
          % (total, len(deferred)))



def submit_second_group(prepared, ring_now=True, fast=False):
    """Stage a second group into a world firmware is already running, and ring for it.

    The first group runs only because it is visible when the control start arrives. A driver needs
    the ones after it to run at a doorbell, which is a different question and has never been asked
    here: this path has always staged exactly one group.
    """
    submitter = prepared["submitter"]
    channels = prepared["channels"]
    read = prepared["read"]
    again = prepared["stage_again"]
    if not again:
        print("nothing recorded for a second group")
        return {}
    # A witness for this group alone. The extent count and the output comparison are cumulative and
    # cannot separate a second group's work from the first's; the stage status objects and a sample
    # of the extent taken either side of it can.
    witness = {} if fast else (prepared.get("second_witness") or {})
    if fast:
        print("  immediate mode: skipped the pre-submit page witness")
    def read_control_cursor(label):
        """The shared control object's cursor, which firmware advances when it acts on an entry."""
        pa = prepared["arena"].physical(SHARED_CONTROL_ADDRESS)
        if pa is None:
            return None
        p.dc_civac(pa, PAGE)
        value = struct.unpack_from(
            "<I", bytes(iface.readmem(pa + SHARED_CONTROL_COUNT_AT, 4)), 0)[0]
        print("  shared control cursor %s: %#x" % (label, value))
        return value

    if (SECOND_GROUP_ANNOUNCED_CONTROL[0] or SECOND_GROUP_ANNOUNCED_20[0]
            or SECOND_GROUP_RUNTIME_20[0]):
        read_control_cursor("before the runtime entries")
        # Every runtime device-control entry this record has published went out unannounced: the
        # ring was written and the producer bumped, and nothing told firmware to look. A working
        # host sends a 0x84 for each one, which is the most common message in its trace. So the
        # standing observation that firmware consumes no device control after the opening was never
        # a test of an announced entry.
        if SECOND_GROUP_RUNTIME_20[0]:
            # A host's order, read from its ring: the bare 0x2e occupies the slot before the
            # runtime registration, so it goes first.
            bare = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<I", bare, 0, 0x2e)
            announce_control_entry(prepared["instances"][0], prepared["ascs"][0],
                                   bytes(bare), "runtime 0x2e")
            announce_control_entry(prepared["instances"][0], prepared["ascs"][0],
                                   build_control_20_entry_runtime(),
                                   "runtime 0x20 (slot 22, count 0x38)")
            # The secondary's ring grows too, and nothing this path does has ever published on it
            # at runtime. A host's holds sixteen entries at its first work doorbell and twenty-one
            # at its second: five further 0x22 entries, each carrying its subtype and nothing else.
            bare22 = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<I", bare22, 0, 0x22)
            if SECONDARY_ANNOUNCE_SWEEP[0]:
                # The secondary does not consume an entry announced with the primary's payload, and
                # the payload for the secondary has never been observed: the mailbox trace that
                # gave the primary's was hooked on one endpoint. Publishing is cheap, so sweep the
                # candidates in one run rather than one boot each.
                taken = []
                for payload in range(SECONDARY_ANNOUNCE_SWEEP[0]):
                    result = announce_control_entry(
                        prepared["instances"][1], prepared["ascs"][1],
                        bytes(bare22), "secondary 0x22 payload %#04x" % payload,
                        payload=payload)
                    if result.get("consumed"):
                        taken.append(payload)
                print("  secondary announcement payloads that were taken: %s"
                      % (", ".join("%#04x" % v for v in taken) if taken else "none"))
            else:
                for index in range(SECONDARY_RUNTIME_ENTRIES):
                    announce_control_entry(
                        prepared["instances"][1], prepared["ascs"][1],
                        bytes(bare22), "secondary runtime 0x22 %d" % index)
                if SECONDARY_CONTROL_START[0]:
                    # The secondary consumed its sixteen opening entries, and it consumed them at
                    # the control start rather than at any announcement. So a control start, not a
                    # 0x84, may be what makes it scan its control channel. Send one and look again.
                    states = prepared["instances"][1]["channel_state_pas"][
                        g17p.CHANNEL_TABLE_WORK_COUNT]
                    before = [struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0]
                              if pa else 0 for pa in states[:3]]
                    prepared["ascs"][1].db.send(DoorbellMsg(
                        TYPE=g17p.MSG_CONTROL_START,
                        CHANNEL=g17p.CONTROL_START_CHANNEL))
                    time.sleep(0.05)
                    for pa in states[:3]:
                        if pa:
                            p.dc_civac(pa, 8)
                    after = [struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0]
                             if pa else 0 for pa in states[:3]]
                    print("  secondary control start: %s -> %s  %s"
                          % (before, after,
                             "consumed" if after[0] > before[0] else "not consumed"))
        if SECOND_GROUP_ANNOUNCED_20[0]:
            # The opening's own registration entry, resent while firmware runs. It names the shared
            # control object and the operand table, and the shared control object is one of the two
            # things firmware writes when it dispatches and never touches when it declines.
            announce_control_entry(prepared["instances"][0], prepared["ascs"][0],
                                   build_control_20_entry(), "announced 0x20")
        body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into("<II", body, 0, 0x2e, 0)
        for index in range(SECOND_GROUP_ANNOUNCED_CONTROL[0]):
            struct.pack_into("<I", body, 4, index)
            announce_control_entry(prepared["instances"][0], prepared["ascs"][0],
                                   bytes(body), "announced 0x2e %d" % index)
        read_control_cursor("after the runtime entries")
    if SECOND_GROUP_CLEAR_POOLS[0]:
        # Firmware links a job record out of record pool A and, on the first group, unlinks it again
        # on completion. On a second group it links the same address, `pool A + 0x100`, and leaves
        # it there. Whatever it wrote into that pool while completing the first group is still
        # present. Clear both pools so a later group cannot be finding a record that is already
        # accounted for.
        arena = prepared["arena"]
        cleared = []
        for name in ("record_pool_a", "record_pool_b"):
            record = next((entry for entry in arena.entries
                           if entry["name"] == name), None)
            if record is None:
                continue
            p.memset32(record["pa"], 0, PAGE)
            p.dc_civac(record["pa"], PAGE)
            cleared.append(name)
        u.inst("dsb sy")
        print("  cleared %s before the second group" % ", ".join(cleared))
    if SECOND_GROUP_HOST_DELTA[0]:
        # What a working host's firmware state looks like when it is about to dispatch its second
        # group, rather than what ours looks like after its first. Two captures of the same machine
        # one work doorbell apart differ in 42 of the 626 shared pages; this writes the later
        # content into every one of them that exists here. Restricted by --second-group-delta-only
        # for bisecting once it does something.
        later = Capture(SECOND_SNAPSHOT)
        first_capture = prepared["capture"]
        earlier = first_capture.by_root[first_capture.selected_root]
        uat = prepared["uat"]
        only = SECOND_GROUP_DELTA_ONLY[0]
        written = pages = 0
        for va, (index, _pte) in sorted(later.by_root[later.selected_root].items()):
            if va not in earlier:
                continue
            if only is not None and va not in only:
                continue
            after = later.blob(index)
            before = first_capture.blob(earlier[va][0])
            if after == before:
                continue
            pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
            if pa is None:
                continue
            p.dc_civac(pa, PAGE)
            ours = bytearray(iface.readmem(pa, PAGE))
            changed = 0
            for offset in range(PAGE):
                if after[offset] != before[offset]:
                    ours[offset] = after[offset]
                    changed += 1
            if changed:
                iface.writemem(pa, bytes(ours))
                p.dc_civac(pa, PAGE)
                written += changed
                pages += 1
        u.inst("dsb sy")
        print("  applied a host's first-to-second doorbell delta: %d bytes over %d pages"
              % (written, pages))
    if SECOND_GROUP_GROW[0]:
        # A working host's firmware context is 626 pages at its first work doorbell and 658 at its
        # second. The 32 it gains are not incidental: two of them are the created queue pair's
        # pointer block and its item ring, and the ring holds exactly a second submission's three
        # item addresses. Two eight-page runs hold records naming the second descriptors and the
        # created pair's queue records. This path has never mapped any of it, so firmware has been
        # asked to dispatch a second group into a context that lacks the pages a host gives it.
        growth = Capture(SECOND_SNAPSHOT)
        first_capture = prepared["capture"]
        base = first_capture.by_root[first_capture.selected_root]
        uat = prepared["uat"]
        arena = prepared["arena"]
        mapped = blank = already = 0
        created_pages = set()
        for spec in CREATED_QUEUE_PAIR:
            for label in ("pointers", "ring"):
                created_pages.add(spec[label] & ~(PAGE - 1))
        for va, (index, pte) in sorted(growth.by_root[growth.selected_root].items()):
            if va in base:
                continue
            if va in created_pages:
                # The created pair's own pointer block and item ring. Seeding them from a capture
                # would put a host's indices back, and its write index is already at three, which
                # is how a freshly built pair ended up staging from slot three.
                already += 1
                continue
            if arena.physical(va) is not None:
                # Already placed here, by the created queue pair among others. Mapping a fresh page
                # over it would orphan what was written there, which is how the item rings were
                # losing their published addresses before.
                already += 1
                continue
            body = growth.blob(index)
            pa = u.memalign(PAGE, PAGE)
            if any(body):
                iface.writemem(pa, body)
                mapped += 1
            else:
                p.memset32(pa, 0, PAGE)
                blank += 1
            p.dc_civac(pa, PAGE)
            uat.iomap_at(CONTEXT, va, pa, PAGE,
                         AttrIndex=(pte >> 2) & 7, AP=1, UXN=(pte >> 54) & 1)
            arena.entries.append({"name": "growth_%#x" % va, "va": va,
                                  "pa": pa, "size": PAGE})
        uat.flush_dirty()
        uat.invalidate_cache()
        print("  grew the firmware context by %d pages with content and %d blank, "
              "%d already placed here, as a host's is at its second doorbell"
              % (mapped, blank, already))
    if SECOND_GROUP_RESTORE[0]:
        # Put firmware's own context back to what it held before it dispatched the first group.
        # Everything the host controls has been excluded, so if the one-group limit lives in
        # firmware's state this is where it is, and restoring that state should release the next
        # group. Pages the first group's dispatch did not change are written back unchanged, which
        # costs nothing and keeps the restore honest.
        directory = pathlib.Path(SECOND_GROUP_RESTORE[0])
        uat = prepared["uat"]
        restored = skipped = 0
        for path in sorted(directory.glob("*.bin")):
            va = int(path.stem, 16)
            pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
            if pa is None:
                skipped += 1
                continue
            body = path.read_bytes()[:PAGE]
            if len(body) < PAGE:
                body = body + bytes(PAGE - len(body))
            iface.writemem(pa, body)
            p.dc_civac(pa, PAGE)
            restored += 1
        u.inst("dsb sy")
        print("  restored %d firmware pages to their pre-dispatch content, %d not mapped"
              % (restored, skipped))
    if SECOND_GROUP_REWIND[0]:
        # Make the queues look as they did before the first group: indices back to zero, the ring
        # slot the first group announced cleared, and the channel producer back to zero. If a group
        # then executes, what stops a later one is per-queue index state that a host could manage;
        # if it does not, the limit is firmware's own and no host bookkeeping reaches it.
        backend = load_backend_modules().g17p_backend
        channels = prepared["channels"]
        rewound = []
        for name, spec in again.items():
            queue = spec["queue"]
            pointers_pa = prepared["arena"].physical(queue.pointers_addr)
            if pointers_pa is not None:
                for offset in (g17p.QUEUE_PTR_DONE, g17p.QUEUE_PTR_READ,
                               g17p.QUEUE_PTR_WRITE):
                    iface.writemem(pointers_pa + offset, struct.pack("<I", 0))
                p.dc_civac(pointers_pa & ~(PAGE - 1), PAGE)
            entry = channels.by_name(name)
            ring_pa = prepared["arena"].physical(entry["ring_addr"])
            if ring_pa is not None:
                p.memset32(ring_pa, 0, g17p.RING_SLOT_SIZE)
                p.dc_civac(ring_pa & ~(PAGE - 1), PAGE)
            producer_pa = prepared["arena"].physical(entry["state_addrs"][2])
            if producer_pa is not None:
                iface.writemem(producer_pa, struct.pack("<I", 0))
                p.dc_civac(producer_pa & ~(PAGE - 1), PAGE)
            rewound.append(name)
        u.inst("dsb sy")
        print("  rewound %s to their pre-submission indices" % ", ".join(sorted(rewound)))
    if SECOND_GROUP_MAP_CYCLE[0]:
        # A host maps 198 times and unmaps once between its submissions; this path never touches its
        # tables after firmware starts. The maintenance alone is not the mechanism, so do the thing
        # itself: map a page that was not mapped, then take it away again. The address is chosen
        # well above anything this world uses, so nothing in the submission depends on it and the
        # only effect is that the tables changed.
        uat = prepared["uat"]
        page = u.memalign(PAGE, PAGE)
        p.memset32(page, 0, PAGE)
        p.dc_civac(page, PAGE)
        cycles = SECOND_GROUP_MAP_CYCLE[0]
        # A host's pattern: the same address every time, a different physical page each time, and
        # one unmap at the end. Not one address per page, which is what this used to do.
        for _index in range(cycles):
            fresh = u.memalign(PAGE, PAGE)
            p.memset32(fresh, 0, PAGE)
            p.dc_civac(fresh, PAGE)
            uat.iomap_at(CONTEXT, MAP_CYCLE_VA_BASE, fresh, PAGE,
                         AttrIndex=MemoryAttr.Shared, AP=1, UXN=1)
            uat.flush_dirty()
            uat.invalidate_cache()
        uat.iomap_at(CONTEXT, MAP_CYCLE_VA_BASE, 0, PAGE,
                     AttrIndex=MemoryAttr.Shared, AP=1, UXN=1)
        uat.flush_dirty()
        uat.invalidate_cache()
        u.inst("dsb sy")
        print("  fed %d pages through %#x and released it, as a host does between submissions"
              % (cycles, MAP_CYCLE_VA_BASE))

    if SECOND_GROUP_REINIT[0]:
        # Firmware is handed its descriptor once and never again. Nothing has tested what a second
        # one does to a running instance. If the allowance is bound to an initialisation rather than
        # to the boot, re-handing the descriptor is the only way to reach it without restarting the
        # core, which is documented as impossible.
        instances = prepared["instances"]
        ascs = prepared["ascs"]
        for index, entry in enumerate(instances):
            root = entry.get("root_va")
            if not root:
                continue
            # The same encoding the boot uses: the address is the low 44 bits, not the low 48.
            # Sending the 48-bit form crashed both instances, which was this mistake and not a
            # property of re-initialisation.
            message = InitMsg(TYPE=g17p.MSG_INITDATA,
                              INITDATA=root & ((1 << 44) - 1))
            ascs[index].db.send(message)
            print("  re-sent initdata to %s: %#x" % (entry["name"], int(message.value)))
            time.sleep(CONTROL_START_GAP_MS / 1000.0)
        u.inst("dsb sy")
        time.sleep(0.2)

    if SECOND_GROUP_RESEED:
        # Put content back into render pages this run deliberately left blank, so a first group can
        # be made to dispatch without executing and a second can then be given what it needs. That
        # separates the two readings of the one-group limit: whether it counts dispatches or
        # executions.
        capture = prepared["capture"]
        extent = prepared.get("render_extent") or {}
        for va in sorted(SECOND_GROUP_RESEED):
            pa = extent.get(va)
            if pa is None:
                print("  %#x is not in the render extent; not reseeded" % va)
                continue
            body = capture.page(va)
            iface.writemem(pa, body)
            p.dc_civac(pa, PAGE)
            print("  reseeded %#x with %d non-zero bytes"
                  % (va, sum(1 for b in body if b)))
        u.inst("dsb sy")

    if SECOND_GROUP_INVALIDATE[0]:
        # A working host edits its translation tables between submissions: 198 map-begin calls and
        # one unmap-begin, where this path builds its tables before firmware starts and never
        # touches them again. The cheapest reproduction of the effect is the maintenance a table
        # edit performs, a dirty flush and a cache invalidate, without changing any mapping.
        prepared["uat"].flush_dirty()
        prepared["uat"].invalidate_cache()
        u.inst("dsb sy")
        print("  flushed and invalidated the translation tables, as a table edit would")

    if SECOND_GROUP_RESTORE_RENDER[0]:
        # The pages the accelerator writes are pages it also reads, measured: clearing exactly the
        # 920 it changes stops the render entirely. After a dispatch those pages hold the first
        # render's output, which is not the state a first submission is given. Put them back to
        # what they held before it ran: the seeded body where there was one, zeros where the page
        # was mapped blank. This is the restore the clearing attempts should have been.
        extent = prepared.get("render_extent") or {}
        bodies = prepared.get("render_bodies") or {}
        restored = blanked = 0
        for va, pa in extent.items():
            body = bodies.get(va)
            if body is None:
                p.memset32(pa, 0, PAGE)
                blanked += 1
            else:
                iface.writemem(pa, body)
                restored += 1
            p.dc_civac(pa, PAGE)
        u.inst("dsb sy")
        print("  restored the render context to its pre-dispatch state: %d pages reseeded, "
              "%d blanked" % (restored, blanked))
    if SECOND_GROUP_RESET_CURSOR[0]:
        # Firmware writes the shared control object when it dispatches and never touches it when it
        # declines. Its cursor is the one field known to move across a dispatch, from the value a
        # host builds to the value firmware leaves. Put it back and see whether a second group is
        # dispatched, which would make the object a per-submission handshake rather than a one-off
        # registration.
        arena = prepared["arena"]
        pa = arena.physical(SHARED_CONTROL_ADDRESS)
        if pa is None:
            print("  shared control object is not in the arena; cursor not reset")
        else:
            p.dc_civac(pa, PAGE)
            page = bytearray(iface.readmem(pa, PAGE))
            was_count = struct.unpack_from("<I", page, SHARED_CONTROL_COUNT_AT)[0]
            struct.pack_into("<I", page, SHARED_CONTROL_COUNT_AT,
                             SHARED_CONTROL_COUNT_BEFORE)
            iface.writemem(pa, bytes(page))
            p.dc_civac(pa, PAGE)
            inner_pa = arena.physical(SHARED_CONTROL_INNER_ADDRESS)
            was_inner = None
            if inner_pa is not None:
                p.dc_civac(inner_pa, PAGE)
                inner = bytearray(iface.readmem(inner_pa, PAGE))
                was_inner = inner[0]
                inner[0] = SHARED_CONTROL_INNER_BEFORE
                iface.writemem(inner_pa, bytes(inner))
                p.dc_civac(inner_pa, PAGE)
            u.inst("dsb sy")
            print("  shared control cursor %#x -> %#x, inner byte %s -> %d"
                  % (was_count, SHARED_CONTROL_COUNT_BEFORE,
                     was_inner if was_inner is not None else "?",
                     SHARED_CONTROL_INNER_BEFORE))
    if SECOND_GROUP_RESET_RENDER[0]:
        # The first render wrote 920 pages of accelerator output and left the tiler's own metadata
        # holding where it got to. A second group names the same metadata, so it inherits a used
        # heap rather than the empty one a first submission is given. Put the pages a fresh
        # submission expects blank back the way they started, and see whether that is the
        # difference. Nothing in the submission structures is touched.
        restored = 0
        for record in prepared.get("render_pages") or ():
            if record.get("source") != "zero":
                continue
            p.memset32(record["pa"], 0, PAGE)
            p.dc_civac(record["pa"], PAGE)
            restored += 1
        extent = prepared.get("render_extent") or {}
        seeded_vas = prepared.get("render_seeded_vas") or set()
        cleared = 0
        for va, pa in extent.items():
            if va in seeded_vas:
                continue
            p.memset32(pa, 0, PAGE)
            cleared += 1
        if cleared:
            p.dc_civac(min(extent.values()), PAGE)
        print("  reset %d render pages a fresh submission is given blank, and %d extent pages "
              "the first render wrote into" % (restored, cleared))
    # Sample after any reset, not before it. Sampling first records this path's own zeroing as a
    # change the second group made, which is the opposite of what the witness is for.
    sample_before = {}
    for name, pa in witness.items():
        p.dc_civac(pa, PAGE)
        sample_before[name] = bytes(iface.readmem(pa, PAGE))
    if SECOND_GROUP_NEW_QUEUE[0]:
        # Stage the second group onto a pair this host creates, as a working host does.
        pair = build_created_queue_pair(prepared["arena"], prepared["uat"])
        if pair:
            by_kind = {again[name]["kind"]: name for name in again}
            for spec in pair:
                name = by_kind.get(spec["kind"])
                if name is None:
                    continue
                # The backend module is loaded inside the build and is not in scope here, so the
                # existing queue object's own class builds the new one.
                queue = type(again[name]["queue"])(read, spec["record"], spec["grid"])
                # The record page is reached one way through the translation tables, which is where
                # the pair was written, and another through the backend's own heap, which is what
                # this reader uses. The queue therefore parses zeros: no pointer block, no ring and
                # no job list, and staging would write to address zero. The three addresses are
                # known here, so they are set rather than re-read.
                queue.pointers_addr = spec["pointers"]
                queue.item_ring = spec["ring"]
                queue.job_list_addr = CREATED_QUEUE_JOB_LIST
                _ = channels.by_name(name)
                again[name] = dict(again[name], queue=queue,
                                   grid_index=spec["grid"])
                print("  %s will submit through grid %d at %#014x"
                      % (name, spec["grid"], spec["record"]))

    if SECOND_GROUP_CHANNEL_PAIR[0] is not None:
        # Every submission in this record has gone on TA_0 and 3D_0. The channel table has four
        # pairs and the other three have never carried anything. A host uses one pair, which is an
        # observation of a host rather than a constraint that has been tested here.
        index = SECOND_GROUP_CHANNEL_PAIR[0]
        moved = {}
        for name, spec in sorted(again.items()):
            kind = spec["kind"]
            target = ("TA_%d" if kind == "tiling" else "3D_%d") % index
            try:
                channels.by_name(target)
            except KeyError:
                print("  channel %s is absent from the table" % target)
                moved = {}
                break
            moved[target] = dict(spec)
            print("  %s will submit on %s instead" % (name, target))
        if moved:
            again.clear()
            again.update(moved)

    if SECOND_GROUP_FRESH[0]:
        print("Giving the second group its own work items, at slot 2 of each array")
        for name in sorted(again):
            spec = again[name]
            fresh = build_fresh_work_items(prepared["uat"], spec["items"], 1,
                                           spec["kind"])
            again[name] = dict(spec, items=fresh)
            print("  %-6s %s" % (name, " ".join("%#014x" % v for v in fresh)))

    if SECOND_GROUP_NEW_QUEUE[0]:
        # The per-queue context page names the descriptor and queue a submission belongs to. The
        # init pair gets that written when it is built; a group moved onto a created pair kept the
        # init pair's queue address, and after fresh items it would also have kept the first
        # group's descriptor. Both are known only now.
        context_state = prepared.get("context_state")
        if context_state is not None:
            for name, spec in sorted(again.items()):
                write_context_queue_addresses(
                    context_state, spec["kind"], spec["items"][0],
                    spec["queue"].address)

    if SECOND_GROUP_CLEAR_INIT[0]:
        # Take the init pair's work away before the created pair rings. The one run that produced
        # completion writes had the first group staged on the init pair and only denied its
        # doorbell, so which group completed could not be told apart. With the init queues' indices
        # back at zero and the ring slot they announced cleared, the only work firmware can find is
        # the created pair's, and an execution after this belongs to it.
        init_queues = prepared.get("queues") or {}
        cleared = []
        for name, queue in sorted(init_queues.items()):
            pointers_pa = prepared["arena"].physical(queue.pointers_addr)
            if pointers_pa is not None:
                for offset in (g17p.QUEUE_PTR_DONE, g17p.QUEUE_PTR_READ,
                               g17p.QUEUE_PTR_WRITE):
                    iface.writemem(pointers_pa + offset, struct.pack("<I", 0))
                p.dc_civac(pointers_pa & ~(PAGE - 1), PAGE)
            entry = channels.by_name(name)
            ring_pa = prepared["arena"].physical(entry["ring_addr"])
            if ring_pa is not None:
                p.memset32(ring_pa, 0, g17p.RING_SLOT_SIZE)
                p.dc_civac(ring_pa & ~(PAGE - 1), PAGE)
            producer_pa = prepared["arena"].physical(entry["state_addrs"][2])
            if producer_pa is not None:
                iface.writemem(producer_pa, struct.pack("<I", 0))
                p.dc_civac(producer_pa & ~(PAGE - 1), PAGE)
            cleared.append(name)
        u.inst("dsb sy")
        print("  cleared the init pair's staging: %s" % ", ".join(cleared))

    if SECOND_GROUP_DELTA[0]:
        # A working host's job list is an empty circular list at every captured point, so it never
        # has deferred jobs pending. One reason firmware might defer instead of dispatch is that it
        # still considers the first group outstanding. Write the per-submission records to the state
        # a working host has once its first submission has completed, then submit.
        applied = 0
        for line in pathlib.Path(SECOND_GROUP_DELTA[0]).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            va_text, off_text, body_text = line.split()
            va = int(va_text, 16)
            offset = int(off_text, 16)
            body = bytes.fromhex(body_text)
            pa = leaf_output(prepared["uat"], NATIVE_FIRMWARE_SLOT, va)
            if pa is None:
                continue
            iface.writemem(pa + offset, body)
            p.dc_civac(pa & ~(PAGE - 1), PAGE)
            applied += len(body)
        u.inst("dsb sy")
        print("  wrote %d bytes of completed-submission state before the second group" % applied)

    if SECOND_GROUP_BUMP[0]:
        print("Advancing the second group's descriptors as a host does between submissions")
        for name in sorted(again):
            spec = again[name]
            # Pool-record indices restart on a fresh queue. The captured grid-2/grid-3 pair's
            # first descriptors use the same first records as grid 0/1; only later descriptors on
            # that queue advance them. The other progress fields still need their native first-item
            # values, and self-relative addresses still follow the relocated descriptor.
            advance_pools = spec["queue"].indices()["write"] != 0
            bump_descriptor(prepared["uat"], spec["items"][0], spec["kind"],
                            advance_pools=advance_pools)
            if SECOND_GROUP_NEXT_ROUND[0]:
                bump_submit_sequence(prepared["uat"], spec["items"][0], spec["kind"])

    if SECOND_GROUP_RECORDS[0]:
        # These are two fixed current-job records, not an append-only array. Working captures keep
        # only +0x00 and +0x40 populated and overwrite them as submissions complete; +0x80 and
        # +0xc0 remain zero. This is an explicit experiment because a native host leaves the
        # records from its previous submission in place when it rings for the next one.
        current = sorted(
            ((spec["kind"], spec["items"][0], spec["queue"].address)
             for spec in again.values()),
            key=lambda record: 0 if record[0] == "tiling" else 1,
        )
        build_per_submission_records(
            prepared["arena"], prepared["uat"], current, start=0)
    if SECOND_GROUP_DUMPS[0]:
        # Firmware's own state either side of a submission it declines to dispatch. The first
        # group's dispatch and this group's refusal are the only two cases available, so what
        # firmware touches differently between them is the closest thing to its scheduler's reason.
        dump_firmware_pages(prepared["uat"], prepared["capture"],
                            pathlib.Path(SECOND_GROUP_DUMPS[0] + "_before"),
                            prepared["instances"])
    # Firmware's own trace, either side of a submission it refuses. It logs timestamped records on
    # the secondary's channel 14 whether or not it dispatches, so the records it adds while refusing
    # are the closest thing to its scheduler saying what it did.
    trace = prepared.get("trace_channel")
    trace_before = None
    if trace:
        for pa in trace.values():
            p.dc_civac(pa & ~(PAGE - 1), PAGE)
        trace_before = struct.unpack(
            "<I", bytes(iface.readmem(trace["producer"], 4)))[0]
        print("firmware's trace stands at %d records" % trace_before)
    if SECOND_GROUP_CONTROL_DONE[0]:
        # A working host sends 0x84 continuously, 158 times across the audit logs, where this path
        # sends one before its first doorbell and nothing after. If firmware releases a completed
        # submission on that message, a host that never sends it leaves the first one outstanding.
        for _ in range(SECOND_GROUP_CONTROL_DONE[0]):
            prepared["ascs"][0].db.send(GpuMsg(0x0084000000000011))
        print("  sent %d control-done messages after the first group completed"
              % SECOND_GROUP_CONTROL_DONE[0])

    def snapshot_job_lists(label):
        snapshots = {}
        for spec in again.values():
            queue = spec["queue"]
            address = queue.job_list_addr
            if not address:
                print("  job list %-6s for %s is zero; its record did not land"
                      % (label, spec.get("kind", "?")))
                continue
            if address in snapshots:
                continue
            body = read(address, g17p.JOB_LIST_SIZE)
            parsed = g17p.parse_job_list(body, address)
            snapshots[address] = dict(parsed, raw=body.hex())
            print("  job list %-6s %#014x: first %#014x last %#014x %s"
                  % (label, address, parsed["first"], parsed["last"],
                     "empty" if parsed["empty"] else "nonempty"))
        return snapshots

    def snapshot_current_jobs(label):
        body = read(PER_SUBMISSION_RECORD_VA, 2 * PER_SUBMISSION_RECORD_STRIDE)
        records = []
        for index in range(2):
            words = struct.unpack_from(
                "<8Q", body, index * PER_SUBMISSION_RECORD_STRIDE)
            record = {
                "header": words[0],
                "kind": words[1],
                "timestamps": list(words[2:6]),
                "descriptor": words[6],
                "queue": words[7],
            }
            records.append(record)
            print("  current job %-6s %d: timestamps %s"
                  % (label, index,
                     " ".join("%#x" % value for value in record["timestamps"])))
        return records

    print("Staging a second group into a running world")
    before = {}
    after = {}
    # The event counter is local to a queue, not global to the channel. In the live stream the
    # first submission on the created grid-2/grid-3 pair carries 0x100 at event +0x08, just like
    # the first submission on the initial pair. It advances to 0x200 only for the next group on
    # that same pair.
    group_number = 1 if SECOND_GROUP_NEW_QUEUE[0] else 2
    job_lists_before = snapshot_job_lists("before")
    current_jobs_before = snapshot_current_jobs("before")
    for name, spec in sorted(again.items()):
        entry = channels.by_name(name)
        before[name] = [struct.unpack("<I", read(addr, 4))[0]
                        for addr in entry["state_addrs"][:3]]
        # Bit 24 set, as a working host has it. The record's own nine-submission measurement found
        # `+0x14` reading 0x1000003 on every one of them, so a host does not clear this bit after
        # its first submission, and staging a second group without it was this path's invention.
        result = submitter.stage(
            spec["entry"], spec["queue"], spec["items"], group_number, slot=1,
            first_submit=not SECOND_GROUP_CLEAR_FIRST[0], kind=spec["kind"],
            announce=(True if SECOND_GROUP_ANNOUNCE[0] else spec["announce"]))
        print("  %s staged in slot %d, write %d -> %d"
              % (name, result["slot"], result["write_before"], result["write_after"]))
    if SECOND_GROUP_EARLY[0] and not ring_now:
        print("  left staged for the control start, as a round's second submission is")
        return {"before": before, "after": {}}
    if not SECOND_GROUP_NO_BELL[0]:
        channel = SECOND_GROUP_BELL_CHANNEL[0]
        prepared["ring"](channel)
        if SECOND_GROUP_RING_BOTH[0]:
            # The work doorbell has only ever gone to the primary. The secondary takes part in the
            # first group's dispatch, producing five report records, and takes no part in any later
            # one; it learns about the first only through the control start. Ring it too.
            for instance_asc in prepared["ascs"]:
                instance_asc.db.send(DoorbellMsg(
                    TYPE=g17p.MSG_WORK_DOORBELL,
                    CHANNEL=SECOND_GROUP_BELL_CHANNEL[0]))
                time.sleep(CONTROL_START_GAP_MS / 1000.0)
            print("  rang the work doorbell on both coprocessors")
        if SECOND_GROUP_DRIVE[0]:
            # A host does not ring once and stop. Its trace alternates the work doorbell and
            # control-done at about one to one, eighty-eight doorbells in one capture. This path has
            # rung once for every group it has ever published.
            for _ in range(SECOND_GROUP_DRIVE[0]):
                prepared["ring"](SECOND_GROUP_BELL_CHANNEL[0])
                prepared["ascs"][0].db.send(GpuMsg(0x0084000000000011))
                time.sleep(CONTROL_START_GAP_MS / 1000.0)
            print("  drove the second group with %d rounds of doorbell and control-done"
                  % SECOND_GROUP_DRIVE[0])
        if SECOND_GROUP_DONE_AFTER[0]:
            # A working host's mailbox trace alternates 0x83 and 0x84 at roughly one to one, and the
            # 0x84 comes *after* the doorbell. Everything this path has sent has gone before it.
            for _ in range(SECOND_GROUP_DONE_AFTER[0]):
                asc_primary = prepared["ascs"][0]
                asc_primary.db.send(GpuMsg(0x0084000000000011))
                time.sleep(CONTROL_START_GAP_MS / 1000.0)
            print("  sent %d control-done after the second doorbell, as a host does"
                  % SECOND_GROUP_DONE_AFTER[0])
        since_first = time.monotonic() - prepared.get(
            "first_work_doorbell_at", time.monotonic())
        print("  rang the work doorbell for the second group, channel %#x, %.3f s "
              "after the first" % (channel, since_first))
    else:
        print("  no work doorbell for the second group")
    if SECOND_GROUP_CONTROL[0]:
        # The first group runs at the control start and nothing runs at a doorbell, so the control
        # start is what dispatches. Send one after the second group and see whether it dispatches
        # that too.
        for index in CONTROL_START_ORDER:
            prepared["ascs"][index].db.send(DoorbellMsg(
                TYPE=g17p.MSG_CONTROL_START,
                CHANNEL=g17p.CONTROL_START_CHANNEL))
            time.sleep(CONTROL_START_GAP_MS / 1000.0)
        print("  sent a control start after the second group")
    event_before = prepared["ascs"][0].fw.events
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            for instance in prepared["ascs"]:
                instance.work_pending()
        time.sleep(0.001)
    event_after = prepared["ascs"][0].fw.events
    job_lists_after = snapshot_job_lists("after")
    current_jobs_after = snapshot_current_jobs("after")
    for name, spec in sorted(again.items()):
        entry = channels.by_name(name)
        after[name] = [struct.unpack("<I", read(addr, 4))[0]
                       for addr in entry["state_addrs"][:3]]
        indices = spec["queue"].indices()
        print("  %-6s counters %s -> %s   done %d of write %d"
              % (name, before[name], after[name], indices["done"], indices["write"]))
    moved = []
    for name, pa in sorted(witness.items()):
        p.dc_civac(pa, PAGE)
        now = bytes(iface.readmem(pa, PAGE))
        n = sum(1 for i in range(PAGE) if now[i] != sample_before[name][i])
        if n:
            moved.append((name, n, now[:16].hex()))
    if SECOND_GROUP_DUMPS[0]:
        dump_firmware_pages(prepared["uat"], prepared["capture"],
                            pathlib.Path(SECOND_GROUP_DUMPS[0] + "_after"),
                            prepared["instances"])
    if trace and trace_before is not None:
        for pa in trace.values():
            p.dc_civac(pa & ~(PAGE - 1), PAGE)
        after_count = struct.unpack(
            "<I", bytes(iface.readmem(trace["producer"], 4)))[0]
        added = after_count - trace_before
        print("  firmware logged %d further trace records while refusing" % added)
        if 0 < added <= 24:
            size = g17p.CONTROL_MESSAGE_SIZE
            ring = trace["ring"]
            for index in range(trace_before, after_count):
                slot = index % 0x80
                p.dc_civac((ring + slot * size) & ~(PAGE - 1), PAGE)
                record = bytes(iface.readmem(ring + slot * size, size))
                if any(record):
                    print("    [%3d] %s" % (index, record[:32].hex()))
    print("  across the second group alone: %d of %d watched pages changed"
          % (len(moved), len(witness)))
    print("  primary firmware events across the second group: %d -> %d"
          % (event_before, event_after))
    for name, n, head in moved:
        print("    %-22s %4d bytes  %s" % (name, n, head))
    return {"before": before, "after": after,
            "moved": [{"name": n, "bytes": c} for n, c, _ in moved],
            "events_before": event_before, "events_after": event_after,
            "job_lists_before": {"%#x" % address: value
                                 for address, value in job_lists_before.items()},
            "job_lists_after": {"%#x" % address: value
                                for address, value in job_lists_after.items()},
            "current_jobs_before": current_jobs_before,
            "current_jobs_after": current_jobs_after}


def drain_report_channels(arena, instances):
    """Acknowledge what firmware has produced on its report channels.

    State pointers zero and two each name a split 0x40-byte counter object. The host-owned counter is
    at the pointed-to address and firmware's peer counter is at +0x20. A native host continuously
    copies each peer into the corresponding host counter. State pointer one is a separate invariant
    parameter and is not an index.
    """
    print("Acknowledging firmware's report channels")
    touched = 0
    for entry in instances:
        for index in sorted(g17p.NATIVE_TRAILING_RING_OFFSETS):
            states, _ring = entry["channels"][index]
            for state_index in (0, 2):
                state = states[state_index]
                host_pa = arena.physical(state) if state else None
                peer_pa = arena.physical(state + 0x20) if state else None
                if not host_pa or not peer_pa:
                    continue
                p.dc_civac(host_pa & ~(PAGE - 1), PAGE)
                peer = struct.unpack(
                    "<I", bytes(iface.readmem(peer_pa, 4)))[0]
                host = struct.unpack(
                    "<I", bytes(iface.readmem(host_pa, 4)))[0]
                if peer == host:
                    continue
                iface.writemem(host_pa, struct.pack("<I", peer))
                p.dc_civac(host_pa & ~(PAGE - 1), PAGE)
                touched += 1
                print("  %s channel %d state %d: host %d -> peer %d"
                      % (entry["name"], index, state_index, host, peer))
    u.inst("dsb sy")
    if not touched:
        print("  nothing outstanding")
    return touched


def read_report_channels(arena, instances, label):
    """Read the channels firmware produces on, which is the one thing it volunteers.

    Channels 13 and 14 are firmware's to write and the host's to consume; a world that renders has
    both carrying entries. Nothing on this path has ever read them. If firmware declines a
    device-control entry or a work group for a reason it reports, this is where the reason is.
    """
    print("Firmware-produced channels %s:" % label)
    report = {}
    for entry in instances:
        for index in sorted(g17p.NATIVE_TRAILING_RING_OFFSETS):
            states, ring_va = entry["channels"][index]
            counters = []
            for address in states:
                pa = arena.physical(address) if address else None
                if pa is None:
                    counters.append(0)
                    continue
                p.dc_civac(pa & ~(PAGE - 1), PAGE)
                counters.append(struct.unpack("<I",
                                              bytes(iface.readmem(pa, 4)))[0])
            # On a work channel the host is the producer and writes index 2. On these channels
            # firmware is the producer, and taking its count from index 2 reported "nothing
            # produced" for a channel reading [8, 5, 0], where firmware had produced eight entries
            # and this path had never read one. Read whenever any counter has moved, and take the
            # count from the largest, since which index firmware uses here is not established.
            produced = max(counters)
            key = "%s_ch%d" % (entry["name"], index)
            report[key] = {"counters": counters, "entries": []}
            print("  %-16s counters %s%s"
                  % (key, counters, "" if produced else "   (nothing produced)"))
            if produced and counters[g17p.CHANNEL_STATE_PRODUCER] != produced:
                print("      firmware's count is not at the host producer index; reading %d "
                      "entries from the largest counter" % produced)
            if produced and not ring_va:
                print("      firmware produced %d entries and this path has no ring address for "
                      "this channel, so it has never read one" % produced)
            if not produced or not ring_va:
                continue
            ring_pa = arena.physical(ring_va)
            if ring_pa is None:
                print("      ring %#x is not in the arena" % ring_va)
                continue
            size = g17p.CONTROL_MESSAGE_SIZE
            p.dc_civac(ring_pa & ~(PAGE - 1), PAGE)
            body = bytes(iface.readmem(ring_pa, min(produced, 8) * size))
            for slot in range(min(produced, 8)):
                record = body[slot * size:(slot + 1) * size]
                if not any(record):
                    continue
                report[key]["entries"].append(record.hex())
                print("      [%2d] %s" % (slot, record.hex()))
    return report


# What firmware leaves in the shared control object once it has performed the opening, which the
# pre-work capture already has and this path reaches only by executing the command list.
SHARED_CONTROL_COUNT_AFTER = 0xb0
SHARED_CONTROL_INNER_AFTER = 2


def read_opening_effect(arena, label):
    """Say whether the `0x20` entry was acted on, not merely counted.

    Its counters moving only say firmware took the entry off the ring. What it does with it is
    visible in three places.  The generic bootstrap advances the shared
    object's cursor and its state byte.  The clean partial-opening graph
    instead presents state byte 2 before publication and final-26.6 only
    advances its cursor from 0xc8 to 0xe0.  The operand table supplies a third
    independent witness.

    This is the parameter-buffer binding, which is the one thing a submission needs that no host
    structure names, so whether it happened is upstream of anything about the work itself.
    """
    state = {}
    shared_address = (PARTIAL_OPENING_SHARED_CONTROL_ADDRESS
                      if PARTIAL_OPENING_GRAPH else SHARED_CONTROL_ADDRESS)
    inner_address = (PARTIAL_OPENING_SHARED_CONTROL_INNER_ADDRESS
                     if PARTIAL_OPENING_GRAPH
                     else SHARED_CONTROL_INNER_ADDRESS)
    cursor_pa = arena.physical(shared_address)
    inner_pa = arena.physical(inner_address)
    table_pa = arena.physical(CONTROL_OPERAND_TABLE_VA)
    operand_slot_offset = (
        PARTIAL_CONTROL_OPERAND_SLOT_OFFSET
        if PARTIAL_OPENING_GRAPH else CONTROL_OPERAND_SLOT_OFFSET)
    for name, pa, offset, size in (
            ("shared_control_cursor", cursor_pa, SHARED_CONTROL_COUNT_AT, 4),
            ("shared_control_inner", inner_pa, 0, 1),
            ("operand_table_slot", table_pa, operand_slot_offset, 8)):
        if pa is None:
            state[name] = None
            continue
        p.dc_civac(pa & ~(PAGE - 1), PAGE)
        raw = bytes(iface.readmem(pa + offset, size))
        state[name] = int.from_bytes(raw, "little")
    print("Opening effect %s:" % label)
    expected_after = (PARTIAL_SHARED_CONTROL_COUNT_AFTER
                      if PARTIAL_OPENING_GRAPH else SHARED_CONTROL_COUNT_AFTER)
    expected_before = (PARTIAL_SHARED_CONTROL_COUNT_BEFORE
                       if PARTIAL_OPENING_GRAPH else SHARED_CONTROL_COUNT_BEFORE)
    expected_inner_before = (2 if PARTIAL_OPENING_GRAPH
                             else SHARED_CONTROL_INNER_BEFORE)
    print("  shared control cursor +%#x  %#x   (a host builds %#x, firmware advances to %#x)"
          % (SHARED_CONTROL_COUNT_AT, state["shared_control_cursor"] or 0,
             expected_before, expected_after))
    print("  its inner object byte 0  %s   (this host profile builds %d)"
          % (state["shared_control_inner"], expected_inner_before))
    print("  operand table slot +%#x  %#x   (empty before the first 0x20)"
          % (operand_slot_offset, state["operand_table_slot"] or 0))
    advanced = (state["shared_control_cursor"] != expected_before
                or state["shared_control_inner"] != expected_inner_before
                or state["operand_table_slot"])
    print("  => the 0x20 %s"
          % ("was acted on" if advanced else "was counted but changed nothing"))
    state["_advanced"] = bool(advanced)
    return state


SAMPLE_REGISTERS = [True]


def sample_accelerator_registers():
    """Read the accelerator's own registers, so a run can say whether it ran.

    Firmware reports the first work group complete and the accelerator writes no render page, and
    every observable so far is firmware's own bookkeeping, which says it believes it ran the work.
    The accelerator's registers are the one witness that is not firmware's account of itself: if
    nothing in them moves across the submission, the cores never started, and if something moves
    they ran and wrote somewhere this path does not look. Those are opposite problems.
    """
    values = {}
    if not SAMPLE_REGISTERS[0]:
        # Presenting the opening as already done leaves the part in a state where even the one
        # window it normally answers for raises an SError at EL2, which kills the run before the
        # doorbell. The read is a witness, not a step, so it can be skipped to see the result.
        return values
    # Only the window the part answers for. Reading the full set of declared windows hangs the
    # proxy, and an earlier probe over a wide range produced an SError storm that killed its run.
    # Two ranges the part is known to answer for: the head of the window, and the block holding the
    # two registers the AXI transition workaround reads and writes, which proves that far into the
    # space is live. Whether any of these moves when a render actually happens is not established, so
    # a run that reports nothing moving is weak on its own; the control is to take the same reading on
    # the replay path, which does render.
    for base in g17p.REGISTER_WINDOW_BASES:
        for offset in (list(range(0, 0x40, 4))
                       + list(range(0x1000100, 0x1000140, 4))):
            try:
                values["%#x+%#x" % (base, offset)] = int(p.read32(base + offset))
            except Exception:
                # A window the part does not answer for is a fact about the part, not a reason to
                # lose the run.
                pass
    return values


def report_accelerator_registers(before, after):
    changed = {name: (before[name], after[name]) for name in sorted(before)
               if name in after and before[name] != after[name]}
    print("Accelerator registers across the submission: %d read, %d changed"
          % (len(before), len(changed)))
    for name, (was, now) in list(changed.items())[:24]:
        print("  %-26s %#010x -> %#010x" % (name, was, now))
    if len(changed) > 24:
        print("  ... %d more" % (len(changed) - 24))
    if not changed:
        # Deliberately not read as "the cores did not start". Whether any of these registers moves
        # when a render does happen is unestablished: taking the same reading on the replay path,
        # which renders, would settle it, but adding the probe there makes that run hang, so the
        # control is unavailable. Without it, nothing moving is consistent with the cores never
        # starting and equally with these particular registers being static either way.
        print("  none of them moved; whether any would move on a render is unestablished, "
              "so this does not by itself say the cores stayed idle")
    return {name: list(pair) for name, pair in changed.items()}


COMPARE_RENDER = [None]
SECOND_GROUP_CONTROL = [False]
SECOND_GROUP_RECORDS = [False]
SECOND_GROUP_DUMPS = [None]
SECOND_GROUP_DELTA = [None]
SECOND_GROUP_NO_BELL = [False]
SECOND_GROUP_CLEAR_FIRST = [False]
SECOND_GROUP_NEW_QUEUE = [False]
SECOND_GROUP_RESET_RENDER = [False]
SECOND_GROUP_ANNOUNCE = [False]
FIRST_DOORBELL_DELAY = [0.0]
SECOND_GROUP_RESET_CURSOR = [False]
SECOND_GROUP_RESTORE_RENDER = [False]
SECOND_GROUP_INVALIDATE = [False]
SECOND_GROUP_MAP_CYCLE = [0]
SECOND_GROUP_RESEED = set()
SECOND_GROUP_REINIT = [False]
# The device address a working host feeds physical pages to between its two submissions: the render
# context's base plus 0x660000. All 198 of its map calls name this one address, cycling four pages
# through it, and its single unmap releases the last of them. Nothing is mapped here in this world.
MAP_CYCLE_VA_BASE = 0x1000660000
SECOND_GROUP_CHANNEL_PAIR = [None]
SECOND_GROUP_REWIND = [False]
SECOND_GROUP_RESTORE = [None]
SECOND_GROUP_RING_BOTH = [False]
NO_FIRST_DOORBELL = [False]
PRE_DOORBELLS = [0]
SECOND_GROUP_GROW = [False]
SECOND_GROUP_HOST_DELTA = [False]
SECOND_GROUP_DONE_AFTER = [0]
SECOND_GROUP_CLEAR_POOLS = [False]
SECOND_GROUP_CLEAR_INIT = [False]
SECOND_GROUP_ANNOUNCED_CONTROL = [0]
SECOND_GROUP_ANNOUNCED_20 = [False]
CONTROL_OPERAND_RUNTIME = [False]
SECOND_GROUP_RUNTIME_20 = [False]
SECOND_GROUP_DELTA_ONLY = [None]
# Changing the render's dimensions changes every generated object that follows them. The workload's
# own content still describes the original size, so a run at a new size is a test of whether the
# path this project builds is parameterised, not a test of the picture.
RENDER_SIZE_OVERRIDDEN = [False]
SIZE_DEPENDENT_PAGES = frozenset(("scissor_array", "bind5_and_deflake"))
# An experiment may replace the first group's render recipe after the generic
# caller-page mapper has completed but before any descriptor or queue object is
# built.  The hook receives only constructed live state; it cannot import
# capture bytes into the submission without tripping the global audit below.
OPENING_RENDER_STATE_HOOK = [None]
SECOND_GROUP_BELL_CHANNEL = [0]
SECOND_GROUP_FRESH = [False]
SECOND_GROUP_CONTROL_DONE = [0]
SECOND_GROUP_BUMP = [False]
SECOND_GROUP_NEXT_ROUND = [False]
SECOND_GROUP_EARLY = [False]


def read_render_witness(render_state):
    """Read back what the accelerator writes when a submission draws.

    The named pages are fourteen of the 3,618 the extent maps, so a submission that executed but
    wrote elsewhere would leave every one of them alone and look exactly like one that did not
    execute. The whole-extent scan against the head samples is the witness; the firmware event
    count is not, having twice been withdrawn as one.
    """
    print("Render witness:")
    state = {}
    for record in render_state["pages"]:
        p.dc_civac(record["pa"], PAGE)
        body = bytes(iface.readmem(record["pa"], PAGE))
        nonzero = sum(byte != 0 for byte in body)
        # Compared by content. Counting non-zero bytes misses any change that keeps the count the
        # same, which for a framebuffer being drawn into is the common case rather than the rare
        # one, and this witness reported "unchanged" for such a page for a long time.
        before = record.get("body")
        differing = (sum(1 for i in range(PAGE) if before[i] != body[i])
                     if before is not None else None)
        state[record["name"]] = {"nonzero": nonzero,
                                 "delta": nonzero - record["nonzero"],
                                 "differing": differing,
                                 "head": body[:16].hex()}
        if differing:
            print("  %-22s %5d bytes differ, non-zero %d -> %d  %s"
                  % (record["name"], differing, record["nonzero"], nonzero,
                     body[:16].hex()))
        elif differing is None and nonzero != record["nonzero"]:
            print("  %-22s %5d -> %-5d non-zero  %s"
                  % (record["name"], record["nonzero"], nonzero, body[:16].hex()))
    unchanged = [name for name, values in state.items()
                 if not (values["differing"] if values["differing"] is not None
                         else values["delta"])]
    print("  %d of %d named pages changed; unchanged: %s"
          % (len(state) - len(unchanged), len(state), ", ".join(sorted(unchanged))))

    extent = render_state["extent"]
    changed = []
    for address, head in sorted(extent["heads"].items()):
        pa = extent["mapped"][address]
        p.dc_civac(pa, PAGE)
        if bytes(iface.readmem(pa, 32)) != head:
            changed.append(address)
    print("  whole extent: %d of %d mapped pages changed in their first 32 bytes"
          % (len(changed), len(extent["heads"])))
    # The accelerator's output region, defined by measurement rather than by which pages this path
    # seeded: exactly the pages a dispatch changed. A witness in another process can clear these
    # and leave every input alone.
    RENDER_WRITTEN_PAGES.extend(changed)

    if COMPARE_RENDER[0]:
        # The only question that settles whether this path renders: is what the accelerator left the
        # same as what a working host's accelerator left, on the pages a working host writes.
        directory = pathlib.Path(COMPARE_RENDER[0])
        same = differ = absent = 0
        worst = []
        for path in sorted(directory.glob("*.bin"), key=lambda q: int(q.stem, 16)):
            va = int(path.stem, 16)
            pa = extent["mapped"].get(va)
            if pa is None:
                absent += 1
                continue
            p.dc_civac(pa, PAGE)
            ours = bytes(iface.readmem(pa, PAGE))
            theirs = path.read_bytes()[:PAGE]
            if ours == theirs:
                same += 1
            else:
                differ += 1
                n = sum(1 for i in range(PAGE) if ours[i] != theirs[i])
                worst.append((va, n))
        print("  against a working host's own output: %d pages identical, %d differ, %d not mapped "
              "here" % (same, differ, absent))
        named = {record["va"]: record["name"] for record in render_state["pages"]}
        for va, n in sorted(worst, key=lambda row: -row[1]):
            print("    %#014x differs in %5d bytes  %s"
                  % (va, n, named.get(va, "")))
    for address in changed[:20]:
        print("    %#x" % address)
    # The changed set is the only direct evidence of how far a dispatch got, so keep all of it
    # rather than the first twenty. Where a contiguous run stops is where to look for the fault.
    render_state["changed"] = changed
    if changed:
        runs = []
        start = prev = changed[0]
        for address in changed[1:]:
            if address == prev + PAGE:
                prev = address
                continue
            runs.append((start, prev))
            start = prev = address
        runs.append((start, prev))
        print("  in %d contiguous runs:" % len(runs))
        for lo, hi in runs:
            print("    %#014x .. %#014x  %d pages"
                  % (lo, hi, (hi - lo) // PAGE + 1))
    if len(changed) > 20:
        print("    ... %d more" % (len(changed) - 20))
    state["_extent_changed"] = ["%#x" % address for address in changed]
    return state


def apply_scalars(arena, instances):
    """Write the scalar fields a working host sets that no pointer walk reaches."""
    root_pa = arena.physical(instances[0]["root_va"])
    main_va = struct.unpack(
        "<Q", iface.readmem(root_pa + build.ROOT_MAIN_CONFIG, 8))[0]
    region_va = struct.unpack("<Q", iface.readmem(root_pa + 0x20, 8))[0]
    for label, dva, fields in (("main configuration object", main_va,
                                MAIN_CONFIG_SCALARS),
                               ("data region", region_va, DATA_REGION_SCALARS)):
        pa = arena.physical(dva)
        if pa is None:
            raise RuntimeError("the %s at %#x is not in the arena" % (label, dva))
        print("  setting the %s's scalar fields at %#x" % (label, dva))
        for offset, value in fields:
            before = struct.unpack("<I", iface.readmem(pa + offset, 4))[0]
            iface.writemem(pa + offset, struct.pack("<I", value))
            print("    +%#06x  %#010x -> %#010x" % (offset, before, value))
        p.dc_civac(pa & ~(PAGE - 1), PAGE)


def main(argv=None, return_state=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="seconds to wait for both acknowledgements")
    parser.add_argument("--read-crash", action="store_true",
                        help="read firmware's crash report when it reports one")
    parser.add_argument("--verbose-asc", type=int, default=0,
                        help="mailbox verbosity for both instances")
    parser.add_argument("--graft", default="all",
                        help="comma-separated initdata regions whose blank fields are filled "
                             "from the capture: hwdata, data_region, status_a, all, none")
    parser.add_argument("--no-seed", default="", metavar="LIST",
                        help="comma-separated capture-derived blocks to stop copying, so what each "
                             "one is actually for can be measured: render-extra (the render "
                             "context's own content), render-named (the seeded named objects), "
                             "pipelines (the compiled load and store programs), fw-content (the "
                             "firmware context's page contents, still mapped), tails (the "
                             "descriptor tails, built from their listed addresses instead), "
                             "submission (the pages the submission's own objects are placed in, "
                             "which the builder then writes its structures into), all")
    parser.add_argument("--require-zero-capture-pages", action="store_true",
                        help="reject every mode that copies captured content into the live "
                             "world and assert that the render-context copy count is zero")
    parser.add_argument("--full-render-extent", action="store_true",
                        help="with strict zero-capture construction, retain every mapped page "
                             "in the observed render address-space shape as fresh zero memory "
                             "instead of mapping only explicit builder-owned objects")
    parser.add_argument("--fast-render-witness", action="store_true",
                        help="sample only explicit render objects during cold boot; shim tests "
                             "use independent caller-owned target pages as their execution witness")
    parser.add_argument("--seed-constructed-attachments", action="store_true",
                        help="diagnostic control: copy the two attachment-state pages that the "
                             "explicit constructor normally builds, to identify missing fields")
    parser.add_argument("--seed-constructed-attachment", action="append",
                        choices=("color_attachment_main", "color_attachment_external"),
                        default=[],
                        help="diagnostic control: copy only the named attachment-state page; "
                             "repeat to select both")
    parser.add_argument("--seed-extra-range", metavar="LO-HI",
                        help="seed the render context's own content only in this half-open device "
                             "address range, leaving the rest of those pages blank, to bisect which "
                             "of them the work needs")
    parser.add_argument("--seed-submission-except", metavar="VA[,VA]",
                        help="place these submission pages blank instead of seeded, to find which "
                             "of their captured content the builder does not write itself")
    parser.add_argument("--seed-extra-except", metavar="LO-HI[,LO-HI]",
                        help="leave the render context's own content blank in these half-open "
                             "device address ranges, for a leave-one-out sweep of what the work "
                             "actually needs")
    parser.add_argument("--zero-render-bytes", metavar="LO-HI[,LO-HI]",
                        help="experiment-only: zero byte subranges inside seeded render pages")
    parser.add_argument("--render-payload-manifest", metavar="PATH",
                        help="load opaque caller/compiler render pages from a workload manifest")
    parser.add_argument("--shared-control", choices=("before", "after", "mixed"),
                        default="mixed",
                        help="whether the shared control object carries the values a host builds "
                             "or the ones a bound world reads; separated from --opening so the "
                             "two halves of that presentation can be bisected")
    parser.add_argument("--opening", choices=("perform", "done"), default="perform",
                        help="whether firmware performs the device-control opening, or it is "
                             "presented as already done the way the rendering replay world has "
                             "it: shared control object in its after state and the control "
                             "counters already consumed")
    parser.add_argument("--dump-pages", metavar="DIR",
                        help="write this path's content for every firmware-context page as "
                             "<hex dva>.bin, for the replay path to graft over a rendering world")
    parser.add_argument("--scan-blank", action="store_true",
                        help="read every page a working host leaves blank to see what this path "
                             "writes there; costs a proxy round trip per page, so it is off unless "
                             "asked for or implied by a blank-page option")
    parser.add_argument("--skip-input-completeness", action="store_true",
                        help="skip the diagnostic captured-input comparison; useful for execution "
                             "runs where its proxy traffic is not part of the experiment")
    parser.add_argument("--skip-leaf-audit", action="store_true",
                        help="skip the capture-wide translation comparison; execution tests "
                             "should validate only the mappings their pointer closure names")
    parser.add_argument("--blank-like-host", action="store_true",
                        help="zero the pages a working host leaves blank that this path writes "
                             "into, so those pages match a working host's")
    parser.add_argument("--compare-render", metavar="DIR",
                        help="after the run, compare this path's render-context pages against a "
                             "working host's own output for the pages it writes")
    parser.add_argument("--build-dispatch", action="store_true",
                        help="build the dispatch record from constants instead of copying it out "
                             "of a capture")
    parser.add_argument("--build-records", action="store_true",
                        help="build firmware's per-submission records from this path's own "
                             "addresses, instead of replaying them out of a capture")
    parser.add_argument("--apply-delta", metavar="FILE",
                        help="write in everything a first submission changes in the firmware "
                             "context, as a probe of how far firmware gets with that state")
    parser.add_argument("--delta-only", metavar="HEX,HEX",
                        help="restrict --apply-delta to these pages, for bisecting it")
    parser.add_argument("--delta-except", metavar="HEX,HEX",
                        help="exclude these pages from --apply-delta, for bisecting it")
    parser.add_argument("--premap-content", metavar="DIR",
                        help="seed the pre-created pages with the content a world that has run a "
                             "submission has, rather than leaving them blank")
    parser.add_argument("--apply-null-pointers", metavar="FILE",
                        help="pre-fill the firmware-context pointer fields that are null at a "
                             "working host's first work doorbell and set at its second")
    parser.add_argument("--premap-added", metavar="FILE",
                        help="pre-create, blank, the firmware-context pages a first submission adds "
                             "in a working world, so firmware need not create them")
    parser.add_argument("--separate-blank-pages", action="store_true",
                        help="give the eleven measured root/address pairs where native uses a "
                             "distinct blank page their own backing, instead of aliasing content "
                             "from another context")
    parser.add_argument("--blank-only", metavar="HEX,HEX",
                        help="restrict --blank-like-host to these page addresses, for bisecting "
                             "which of them this path's execution depends on")
    parser.add_argument("--fill-missing-input", action="store_true",
                        help="write the capture's byte wherever it has one and this path has zero, "
                             "closing the measured input gap to nothing. Bytes this path set for "
                             "itself are non-zero on both sides and are left alone")
    parser.add_argument("--drain-reports", action="store_true",
                        help="advance the host index on firmware's report channels before the "
                             "second group, in case it will not dispatch until its completions "
                             "have been taken")
    parser.add_argument("--second-group-early", action="store_true",
                        help="stage the second group before the control start, so both submissions "
                             "of a round are in flight together as a working host has them")
    parser.add_argument("--second-group-next-round", action="store_true",
                        help="advance the second group's submit sequence to the next round's "
                             "value, since this path issues it after the first has completed")
    parser.add_argument("--second-group-bump", action="store_true",
                        help="advance the second group's descriptor counters, sequence values and "
                             "self-relative addresses as a host does between submissions")
    parser.add_argument("--second-group-control-done", type=int, default=0, metavar="N",
                        help="send N control-done messages after the first group completes, which "
                             "a working host sends continuously and this path does not")
    parser.add_argument("--second-group-fresh-items", action="store_true",
                        help="give the second group its own descriptor, optional item and event "
                             "item at the next slot of each array, as a host does")
    parser.add_argument("--second-group-bell-channel", type=lambda v: int(v, 0), default=0,
                        metavar="N",
                        help="the work doorbell's channel field for the second group; it encodes "
                             "(queue << 2) | kind, so a group on grid 2 is 8")
    parser.add_argument("--pipeline-tag", action="store_true",
                        help="set the low bit on both pipeline addresses, as the DRM translation "
                             "does; the validated parameters do not carry it and the register "
                             "program passes them through, so the two disagree")
    parser.add_argument("--render-size", metavar="WxH",
                        help="build the render at these dimensions instead of the capture's, to "
                             "test that the objects this path generates really do follow their "
                             "parameters rather than happening to match one capture")
    parser.add_argument("--secondary-control-before", type=int, default=0, metavar="N",
                        help="publish N announced 0x22 entries on the secondary before the first "
                             "work doorbell, to tell a control channel that is dead at runtime "
                             "from one the first dispatch stops")
    parser.add_argument("--second-group-drive", type=int, default=0, metavar="N",
                        help="after the second group's doorbell, send N further rounds of doorbell "
                             "and control-done, which is how a host drives its coprocessor rather "
                             "than ringing once")
    parser.add_argument("--secondary-control-start", action="store_true",
                        help="after publishing the secondary's runtime entries, send it a control "
                             "start; it consumed its opening entries at one rather than at any "
                             "announcement")
    parser.add_argument("--secondary-announce-sweep", type=int, default=0, metavar="N",
                        help="with --second-group-runtime-20, try announcement payloads 0..N-1 on "
                             "the secondary's control channel and report which it consumes")
    parser.add_argument("--second-group-runtime-20", action="store_true",
                        help="build the operand table with the 24 entries a host has by its second "
                             "work doorbell, and publish the runtime registration entry it sends "
                             "between its two submissions: slot 22, command count 0x38")
    parser.add_argument("--second-group-announced-20", action="store_true",
                        help="resend the opening's registration entry, announced, while firmware "
                             "runs and before the second group is staged")
    parser.add_argument("--second-group-announced-control", type=int, default=0,
                        metavar="N",
                        help="publish N runtime device-control entries with the 0x84 announcement "
                             "a host sends for each, before staging the second group; every "
                             "runtime entry this record has published went out unannounced")
    parser.add_argument("--second-group-clear-init", action="store_true",
                        help="clear the init pair's queue indices and announced ring slot before "
                             "the second group rings, so work found afterwards can only be the "
                             "second group's")
    parser.add_argument("--second-group-clear-pools", action="store_true",
                        help="zero both record pools before staging the second group; firmware "
                             "links its job record out of pool A and leaves the second group's "
                             "there, on the same address the first used")
    parser.add_argument("--second-group-done-after", type=int, default=0, metavar="N",
                        help="send N control-done messages after the second group's doorbell; a "
                             "host's trace alternates the doorbell and control-done at about one "
                             "to one, with the control-done after, and this path has only ever "
                             "sent them before")
    parser.add_argument("--second-group-host-delta", action="store_true",
                        help="write what changed in a working host's firmware context between its "
                             "first work doorbell and its second into this world, before staging "
                             "the second group")
    parser.add_argument("--second-group-delta-only", metavar="VA[,VA]",
                        help="restrict --second-group-host-delta to these pages, for bisecting it")
    parser.add_argument("--second-group-grow", action="store_true",
                        help="map the 32 pages a working host's firmware context gains between its "
                             "first work doorbell and its second, with their content, before "
                             "staging the second group")
    parser.add_argument("--pre-doorbells", type=int, default=0, metavar="N",
                        help="ring N work doorbells before the group is published, to tell whether "
                             "the one-group limit counts doorbells or groups taken")
    parser.add_argument("--no-first-doorbell", action="store_true",
                        help="publish the first group and never ring for it, to separate being "
                             "dispatched by the doorbell from being visible while firmware works "
                             "through the opening")
    parser.add_argument("--second-group-ring-both", action="store_true",
                        help="ring the work doorbell on both coprocessors for the second group; it "
                             "has only ever gone to the primary, and the secondary takes part in "
                             "the first group's dispatch but no later one")
    parser.add_argument("--second-group-restore", metavar="DIR",
                        help="write this dump of firmware's context back before staging the second "
                             "group, to test whether the one-group limit lives in state firmware "
                             "changed while dispatching the first")
    parser.add_argument("--second-group-rewind", action="store_true",
                        help="put both queues' indices, announced ring slot and channel producer "
                             "back to their pre-submission values before staging the second group, "
                             "so it is presented to firmware as a first one")
    parser.add_argument("--first-channel-pair", type=int, default=0, metavar="N",
                        help="stage the first group through transport channels TA_N/3D_N")
    parser.add_argument("--first-descriptor-pair", type=int, default=None,
                        metavar="N",
                        help="use local descriptor pair N and grids 2N/2N+1; "
                             "defaults to the transport pair for compatibility")
    parser.add_argument("--second-group-channel-pair", type=int, default=None, metavar="N",
                        help="stage the second group on channel pair N, TA_N and 3D_N, instead of "
                             "the pair every submission in this record has used")
    parser.add_argument("--second-group-reinit", action="store_true",
                        help="re-send the initdata descriptor to both running instances before the "
                             "second group; firmware is handed it once and never again, and nothing "
                             "has tested what a second one does")
    parser.add_argument("--second-group-reseed", metavar="VA[,VA]",
                        help="write the capture's content back into these render pages before the "
                             "second group, so a first group can be dispatched without executing "
                             "and a second given what it needs")
    parser.add_argument("--second-group-map-cycle", type=int, default=0, metavar="N",
                        help="map and then unmap N pages before the second group, which is what a "
                             "host does to its tables between submissions and this path never does")
    parser.add_argument("--second-group-invalidate", action="store_true",
                        help="flush and invalidate the translation tables before the second group, "
                             "which is the maintenance a host's map and unmap calls perform")
    parser.add_argument("--second-group-restore-render", action="store_true",
                        help="put the render context back to the exact state it held before the "
                             "first dispatch, reseeding every page that had content and blanking "
                             "the rest, before staging the second group")
    parser.add_argument("--second-group-reset-cursor", action="store_true",
                        help="put the shared control object's cursor back to the value a host "
                             "builds before staging the second group; firmware advances it when it "
                             "dispatches and never touches it when it declines")
    parser.add_argument("--first-doorbell-delay", type=float, default=0.0, metavar="S",
                        help="wait this long before ringing the first group's doorbell, to tell "
                             "whether a group executes because it is early or because it is first")
    parser.add_argument("--second-group-reset-render", action="store_true",
                        help="before staging the second group, put the render pages a fresh "
                             "submission is given blank back the way they started; the first render "
                             "leaves the tiler's own metadata holding where it got to")
    parser.add_argument("--second-group-announce", action="store_true",
                        help="write the queue's has-commands field for the second group even when "
                             "the first was published without it; the startup path scans the queues "
                             "regardless, and a running one may need telling which has work")
    parser.add_argument("--second-group-new-queue", action="store_true",
                        help="stage the second group onto a queue pair this host creates, with its "
                             "own per-submission records, as a working host does")
    parser.add_argument("--second-group-clear-first", action="store_true",
                        help="clear bit 24 in the second group's ring slot; a working host leaves "
                             "it set on every submission, so this is the earlier behaviour")
    parser.add_argument("--second-group-no-bell", action="store_true",
                        help="do not ring the work doorbell for the second group, so a control "
                             "start can see it undeferred")
    parser.add_argument("--second-group-delta", metavar="FILE",
                        help="write this delta before staging the second group, to present the "
                             "first submission as completed")
    parser.add_argument("--second-group-dumps", metavar="PREFIX",
                        help="dump the firmware context either side of the second group, to "
                             "PREFIX_before and PREFIX_after")
    parser.add_argument("--second-group-records", action="store_true",
                        help="overwrite the two fixed current-job records with the second group's "
                             "actual descriptor and queue before publishing it")
    parser.add_argument("--second-group-control", action="store_true",
                        help="send a control start after the second group, since the first group "
                             "runs at a control start and nothing runs at a doorbell")
    parser.add_argument("--second-group", action="store_true",
                        help="after the first group completes, stage a second one and ring for it, "
                             "which is the submission a driver has to be able to make")
    parser.add_argument("--second-group-immediate", action="store_true",
                        help="publish the second group immediately after the first work doorbell, "
                             "before page witnesses or the normal 500 ms observation delay")
    parser.add_argument("--records-after-publish", action="store_true",
                        help="build the per-submission records after the held-back producers are "
                             "published rather than before the control start")
    parser.add_argument("--second-control-start", action="store_true",
                        help="send another control start after publishing, to tell whether it is "
                             "that notification rather than the doorbell that makes firmware run "
                             "a group")
    parser.add_argument("--no-registers", action="store_true",
                        help="skip reading the accelerator's registers, which SErrors at EL2 in "
                             "some states and kills the run before the doorbell")
    parser.add_argument("--defer-channel", metavar="NAME,NAME",
                        help="with --publish-after-control, defer only these channels, so the "
                             "others are visible when firmware performs the opening; use to tell "
                             "which stage faults")
    parser.add_argument("--publish-after-control", action="store_true",
                        help="hold the work channels' producer index back until after the control "
                             "start, which is a working host's own ordering: its capture has the "
                             "opening performed and the work published but not consumed")
    parser.add_argument("--control-count", type=lambda v: int(v, 0), metavar="N",
                        help="override the count in the opening's 0x20 entry, which is how much of "
                             "the command list firmware executes; a working host's is 0x28")
    parser.add_argument("--poke", action="append", metavar="ROOT:DVA:VALUE",
                        help="write a 32-bit value at ROOT:DVA:VALUE before the control start, "
                             "repeatable, for separating the bits of a control field")
    parser.add_argument("--fill-bytes", metavar="HEX,HEX",
                        help="restrict the fill to these byte offsets within each page, for "
                             "bisecting inside a page")
    parser.add_argument("--fill-after-control", action="store_true",
                        help="write the short bytes after the control start rather than before it, "
                             "since their presence beforehand crashes the primary firmware there")
    parser.add_argument("--fill-only", metavar="HEX,HEX",
                        help="restrict --fill-missing-input to these page addresses, for bisecting "
                             "which of the short pages matters")
    parser.add_argument("--dump-pages-early", metavar="DIR",
                        help="dump the firmware pages before the control start, so the dispatch "
                             "that happens there can be diffed against a refusal")
    parser.add_argument("--dump-pages-after", metavar="DIR",
                        help="dump the firmware pages again after the work group is processed, so "
                             "what firmware did with it can be diffed against the state before the "
                             "doorbell")
    parser.add_argument("--dump-pages-late", metavar="DIR",
                        help="dump this path's firmware pages again just before the work doorbell, "
                             "the point a capture is triggered, so the two are comparable")
    parser.add_argument("--dump-include-channel-state", action="store_true",
                        help="include mutable channel-state pages in requested firmware dumps; "
                             "diagnostic only, since grafting them into another timeline is invalid")
    parser.add_argument("--graft-firmware-from", metavar="DIR",
                        help="before the work doorbell, write a rendering world's firmware pages "
                             "from DIR over this world's at the same addresses. The reverse of the "
                             "replay path's graft, and the only direction never run")
    parser.add_argument("--graft-firmware-only", metavar="HEX,HEX",
                        help="restrict --graft-firmware-from to these device addresses, for "
                             "bisecting which of the differing pages matters")
    parser.add_argument("--native-firmware-overlay-late", action="store_true",
                        help="immediately before the work doorbell, replace every firmware-context "
                             "page with the corrected native first-doorbell snapshot")
    parser.add_argument("--native-firmware-overlay-only", metavar="HEX,HEX",
                        help="restrict --native-firmware-overlay-late to these device addresses")
    parser.add_argument("--drop-render-high", action="store_true",
                        help="also zero the render context's high root in the split. A working "
                             "host keeps it, pointing at a table with no mappings, so this is the "
                             "earlier behaviour rather than the observed one")
    parser.add_argument("--macos-context-table", action="store_true",
                        help="build the hardware context table the way a working host's gpu-region "
                             "actually reads: slot 0 tagged 0 and slot 1 tagged 1 for the render "
                             "context, with no firmware-context entry at all")
    parser.add_argument("--control-done-before-doorbell", type=int, default=1, metavar="N",
                        help="send N control-done messages between the control start and the work "
                             "doorbell, which is what macOS's own trapped sequence shows it doing "
                             "and this path did not")
    parser.add_argument("--drain-post-ack", action="store_true",
                        help="drain both ASC outboxes after their initdata acknowledgements and "
                             "before control start, matching native ordering of the secondary's "
                             "unsolicited 0x42 event")
    parser.add_argument("--drain-native-control-events", action="store_true",
                        help="after the initial 0x84, drain the one primary and eight secondary "
                             "0x42 events observed before macOS rings its first work doorbell")
    parser.add_argument("--native-mailbox-order", action="store_true",
                        help="send the initial 0x84 before reading any post-control-start events, "
                             "then drain the native one-primary/eight-secondary event barrier")
    parser.add_argument("--pre-work-interleave", type=int, default=0, metavar="N",
                        help="send N rounds of 0x87 and 0x84 before the work doorbell, which is how "
                             "a booted host drives the coprocessor continuously and this path never "
                             "has in any world")
    parser.add_argument("--control-ticks", type=int, default=0, metavar="N",
                        help="publish N runtime device-control entries before the work doorbell, "
                             "which is what a booted host sends per doorbell and this path has "
                             "never produced")
    parser.add_argument("--restart-immediately", action="store_true",
                        help="stop and restart both cores right after the first start, with nothing "
                             "built, as a control for whether a restart works at all here")
    parser.add_argument("--restart-after-build", action="store_true",
                        help="stop and restart both coprocessor cores once everything is built, so "
                             "the work is present in memory before firmware begins running, which "
                             "is the side of the boundary a replay's work is on")
    parser.add_argument("--build-before-start", action="store_true",
                        help="build and stage everything before starting the coprocessor cores, "
                             "which is the order the replay path has, rather than starting them "
                             "first")
    parser.add_argument("--start-smc", action="store_true",
                        help="bring the management coprocessor up before the accelerator, so the "
                             "power handshake a full operating system completes is present")
    parser.add_argument("--no-place-submission", action="store_true",
                        help="leave the submission objects in the backend heap instead of placing "
                             "them at the addresses a working host uses")
    parser.add_argument("--no-context-zero", action="store_true",
                        help="do not give context 0 its own table; it then sees the render "
                             "context's attributes for the low alias region")
    parser.add_argument("--no-announce", action="store_true",
                        help="do not write the queue record's has-commands field. A working host "
                             "leaves it zero on every queue, including one still in use, so "
                             "setting it is a field this path sets and a host does not")
    parser.add_argument("--empty-operand-table", action="store_true",
                        help="leave the operand table empty, as the pre-work capture has it, "
                             "instead of filling it the way a world that renders does")
    parser.add_argument("--seed-region", default="",
                        help="comma-separated device-tree carveouts to seed from the capture "
                             "before the coprocessors start, e.g. "
                             "gfx-shared-region,gfx-shared-l2-region")
    parser.add_argument("--original-pa", action="store_true",
                        help="place the firmware extent at the physical addresses the capture had, "
                             "as the replay path restores it. The replay renders with fresh pools "
                             "and while performing the opening, so this is the last measurable "
                             "difference in the world other than the tables themselves")
    parser.add_argument("--render-original-pa", action="store_true",
                        help="map the render context at the physical addresses the capture had, "
                             "as the replay path restores it, instead of fresh memory")
    parser.add_argument("--split-context", choices=("never", "before", "after"),
                        default="after",
                        help="when to take the low root off the firmware slot and the high root "
                             "off the render slot, as a working host's table reads. Applying it "
                             "before the descriptor prevents the parameter-buffer binding; "
                             "applying it after places the split between the binding and the "
                             "work, which is the only ordering both observations allow")
    args = parser.parse_args(argv)
    CAPTURE_WRITE_AUDIT.clear()
    CAPTURE_READ_AUDIT.clear()
    STRICT_SOURCE_BOOT[0] = bool(args.require_zero_capture_pages)
    FAST_RENDER_WITNESS[0] = args.fast_render_witness
    SEED_CONSTRUCTED_ATTACHMENTS.clear()
    SEED_CONSTRUCTED_ATTACHMENTS.update(args.seed_constructed_attachment)
    if args.seed_constructed_attachments:
        SEED_CONSTRUCTED_ATTACHMENTS.update(
            ("color_attachment_main", "color_attachment_external"))
    timing_last = [time.monotonic()]

    def timing(label):
        now = time.monotonic()
        print("TIMING %-28s %7.3f s" % (label, now - timing_last[0]))
        timing_last[0] = now

    if args.second_group_immediate and not args.second_group:
        parser.error("--second-group-immediate requires --second-group")

    suppressed = (set(SEED_BLOCKS) if args.no_seed.strip() == "all"
                  else {value.strip() for value in args.no_seed.split(",") if value.strip()})
    if suppressed - set(SEED_BLOCKS):
        parser.error("unknown --no-seed block: %s" % sorted(suppressed - set(SEED_BLOCKS)))
    SUPPRESSED_SEED.update(suppressed)
    if args.require_zero_capture_pages:
        violations = []
        if suppressed != set(SEED_BLOCKS):
            violations.append("--no-seed must be all")
        if args.graft != "none":
            violations.append("--graft must be none")
        if args.seed_region:
            violations.append("--seed-region must be empty")
        if args.original_pa or args.render_original_pa:
            violations.append("original physical backing must be disabled")
        if args.graft_firmware_from:
            violations.append("--graft-firmware-from must be disabled")
        if SEED_CONSTRUCTED_ATTACHMENTS:
            violations.append("constructed attachment pages must not be seeded")
        if args.native_firmware_overlay_late:
            violations.append("--native-firmware-overlay-late must be disabled")
        if args.second_group_restore or args.second_group_reseed:
            violations.append("second-group capture restore/reseed must be disabled")
        if args.apply_delta or args.apply_null_pointers:
            violations.append("external firmware delta/pointer overlays must be disabled")
        if args.premap_content:
            violations.append("pre-mapped capture content must be disabled")
        if args.fill_missing_input or args.fill_after_control:
            violations.append("capture-derived input filling must be disabled")
        if (args.second_group_host_delta or args.second_group_grow
                or args.second_group_delta):
            violations.append("second-group capture deltas/growth must be disabled")
        if violations:
            parser.error("--require-zero-capture-pages: " + "; ".join(violations))
        SPARSE_RENDER_EXTENT[0] = not args.full_render_extent
    if args.seed_extra_range:
        low, _, high = args.seed_extra_range.partition("-")
        SEED_EXTRA_RANGE[0] = (int(low, 16), int(high, 16))
    if args.seed_submission_except:
        for value in args.seed_submission_except.split(","):
            if value.strip():
                SEED_SUBMISSION_EXCEPT.add(int(value, 16) & ~(PAGE - 1))
    if args.seed_extra_except:
        for span in args.seed_extra_except.split(","):
            low, _, high = span.strip().partition("-")
            SEED_EXTRA_EXCEPT.append((int(low, 16), int(high, 16)))
    if args.zero_render_bytes:
        for span in args.zero_render_bytes.split(","):
            low, _, high = span.strip().partition("-")
            low, high = int(low, 16), int(high, 16)
            if high <= low:
                parser.error("--zero-render-bytes ranges must be non-empty")
            ZERO_RENDER_BYTE_RANGES.append((low, high))

    SAMPLE_REGISTERS[0] = not args.no_registers
    COMPARE_RENDER[0] = args.compare_render
    SECOND_GROUP_CONTROL[0] = args.second_group_control
    SECOND_GROUP_RECORDS[0] = args.second_group_records
    SECOND_GROUP_DUMPS[0] = args.second_group_dumps
    SECOND_GROUP_DELTA[0] = args.second_group_delta
    SECOND_GROUP_NO_BELL[0] = args.second_group_no_bell
    SECOND_GROUP_CLEAR_FIRST[0] = args.second_group_clear_first
    SECOND_GROUP_NEW_QUEUE[0] = args.second_group_new_queue
    SECOND_GROUP_RESET_RENDER[0] = args.second_group_reset_render
    SECOND_GROUP_ANNOUNCE[0] = args.second_group_announce
    FIRST_DOORBELL_DELAY[0] = args.first_doorbell_delay
    SECOND_GROUP_RESET_CURSOR[0] = args.second_group_reset_cursor
    SECOND_GROUP_RESTORE_RENDER[0] = args.second_group_restore_render
    SECOND_GROUP_INVALIDATE[0] = args.second_group_invalidate
    SECOND_GROUP_MAP_CYCLE[0] = args.second_group_map_cycle
    SECOND_GROUP_REINIT[0] = args.second_group_reinit
    if args.second_group_reseed:
        for value in args.second_group_reseed.split(","):
            if value.strip():
                SECOND_GROUP_RESEED.add(int(value, 16))
    SECOND_GROUP_CHANNEL_PAIR[0] = args.second_group_channel_pair
    FIRST_CHANNEL_PAIR[0] = args.first_channel_pair
    FIRST_DESCRIPTOR_PAIR[0] = args.first_descriptor_pair
    SECOND_GROUP_REWIND[0] = args.second_group_rewind
    SECOND_GROUP_RESTORE[0] = args.second_group_restore
    SECOND_GROUP_RING_BOTH[0] = args.second_group_ring_both
    NO_FIRST_DOORBELL[0] = args.no_first_doorbell
    PRE_DOORBELLS[0] = args.pre_doorbells
    SECOND_GROUP_GROW[0] = args.second_group_grow
    SECOND_GROUP_HOST_DELTA[0] = args.second_group_host_delta
    SECOND_GROUP_DONE_AFTER[0] = args.second_group_done_after
    SECOND_GROUP_CLEAR_POOLS[0] = args.second_group_clear_pools
    SECOND_GROUP_CLEAR_INIT[0] = args.second_group_clear_init
    SECOND_GROUP_ANNOUNCED_CONTROL[0] = args.second_group_announced_control
    SECOND_GROUP_ANNOUNCED_20[0] = args.second_group_announced_20
    SECOND_GROUP_RUNTIME_20[0] = args.second_group_runtime_20
    SECONDARY_ANNOUNCE_SWEEP[0] = args.secondary_announce_sweep
    SECONDARY_CONTROL_START[0] = args.secondary_control_start
    SECOND_GROUP_DRIVE[0] = args.second_group_drive
    SECONDARY_CONTROL_BEFORE[0] = args.secondary_control_before
    CONTROL_OPERAND_RUNTIME[0] = args.second_group_runtime_20
    if args.second_group_delta_only:
        SECOND_GROUP_DELTA_ONLY[0] = {
            int(value, 16) for value in args.second_group_delta_only.split(",") if value.strip()}
    if args.pipeline_tag:
        for name in ("store_pipeline", "load_pipeline"):
            RENDER_PARAMETERS[name] |= 4
        print("Pipeline addresses tagged: store %#x load %#x"
              % (RENDER_PARAMETERS["store_pipeline"], RENDER_PARAMETERS["load_pipeline"]))

    if args.render_size:
        width, _, height = args.render_size.lower().partition("x")
        RENDER_PARAMETERS["width"] = int(width, 0)
        RENDER_PARAMETERS["height"] = int(height, 0)
        RENDER_SIZE_OVERRIDDEN[0] = True
        print("Render size overridden: %d x %d"
              % (RENDER_PARAMETERS["width"], RENDER_PARAMETERS["height"]))
    SECOND_GROUP_BELL_CHANNEL[0] = args.second_group_bell_channel
    SECOND_GROUP_FRESH[0] = args.second_group_fresh_items
    SECOND_GROUP_CONTROL_DONE[0] = args.second_group_control_done
    SECOND_GROUP_BUMP[0] = args.second_group_bump
    SECOND_GROUP_NEXT_ROUND[0] = args.second_group_next_round
    SECOND_GROUP_EARLY[0] = args.second_group_early
    if args.control_count is not None:
        # Set before anything is staged, since the opening's entry is built during the build.
        CONTROL_20_COUNT[0] = args.control_count
        print("The opening's 0x20 carries count %#x rather than the captured 0x28"
              % args.control_count)

    global READ_CRASH, CRASH_OUTPUT_DIR
    READ_CRASH = args.read_crash

    out = ARTIFACTS / ("boot_%s" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    out.mkdir(parents=True, exist_ok=True)
    CRASH_OUTPUT_DIR = out
    print("Boot attempt, artifacts at %s" % out)

    if args.require_zero_capture_pages:
        capture = G17PSourceTopology(
            partial_opening=PARTIAL_OPENING_GRAPH)
        timing("build source topology")
    else:
        capture = Capture(SNAPSHOT)
        timing("load reference metadata")
    sgx = u.adt["/arm-io/sgx"]
    handoff_base = int(sgx.gfx_handoff_base)
    smc = start_management_coprocessor() if args.start_smc else None
    sgx_base = power_on(sgx)
    seeded_regions = (seed_fixed_regions(SNAPSHOT, set(args.seed_region.split(",")))
                      if args.seed_region else [])

    # The region above the coprocessor's private range is where firmware objects are expected to
    # live; this comes from the device tree, not from a capture.
    kern_va_base = (int(sgx.rtkit_private_vm_region_base)
                    + int(sgx.rtkit_private_vm_region_size))
    uat = UAT(iface, u)
    uat.allocator = Heap(kern_va_base + 0x80000000, kern_va_base + 0x81000000, PAGE)
    if legacy_aug5_topology():
        # Before the G15 root-preservation fix, UAT.init() cleared from entry
        # 2.  The August 5 source-render positive therefore rebuilt the host
        # subtree at that entry and later mirrored it into the secondary
        # firmware instance.  Reproduce that lifecycle only for this bounded
        # historical-control experiment; the normal G17 policy retains all
        # three firmware-owned entries.
        uat.kernel_root_preserve_count = 2
        print("  legacy August 5 UAT init will preserve two high-root entries")

    # Address-only discriminator for boot-time UAT identity.  The destination
    # pages come from a native capture, but their contents do not: the low root
    # is cleared here before this path creates any mapping, and the upper root
    # is populated below from the live firmware-created shared root.  Moving a
    # root after initdata acknowledgement cannot test firmware's registration
    # of that root, so these switches deliberately act before initdata exists.
    bootstrap_low_root = (
        native_table_targets("render_low")[()]
        if SOURCE_NATIVE_PHYSICAL_TOPOLOGY
        else os.getenv("G17P_BOOTSTRAP_LOW_ROOT_PA")
    )
    if bootstrap_low_root:
        target = (int(bootstrap_low_root, 0)
                  if isinstance(bootstrap_low_root, str)
                  else int(bootstrap_low_root))
        if target & (PAGE - 1):
            raise RuntimeError(
                "bootstrap low UAT root is not page aligned: %#x" % target)
        if target == uat.ttbr1_base:
            raise RuntimeError(
                "bootstrap low UAT root aliases the shared upper root")
        p.memset32(target, 0, PAGE)
        p.dc_civac(target, PAGE)
        original = uat.ttbr0_base
        uat.ttbr0_base = target
        uat.invalidate_cache()
        uat.invalidate_root_walk_cache()
        print(
            "  using source-built low UAT root at prescribed physical "
            "%#x (allocator root was %#x)" % (target, original),
            flush=True,
        )

    # Clear the hardware context table before starting anything. It lives in the accelerator's
    # gpu-region carveout, which is ordinary DRAM that survives a reboot, so root pointers a previous
    # run left in it are still there. Once this path began building the unused contexts, those stale
    # pointers named tables that no longer exist and the coprocessor failed to boot at all on the
    # following run. m1n1's own initializer only establishes context 0, so it does not clear them.
    # Slots 0, 1 and 7 are left alone: the coprocessor's own boot walks the table, and clearing all
    # of it stops it booting. Only the extra contexts this path builds are cleared, which are the
    # ones whose stale pointers name tables that no longer exist.
    stale = []
    for index in range(uat.NUM_CONTEXTS):
        if index in (0, NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT):
            continue
        if (int(p.read64(uat.gpu_region + index * 16))
                or int(p.read64(uat.gpu_region + index * 16 + 8))):
            stale.append(index)
        p.write64(uat.gpu_region + index * 16, 0)
        p.write64(uat.gpu_region + index * 16 + 8, 0)
    if stale:
        print("  cleared %d stale context table slots from a previous run: %s"
              % (len(stale), stale))
    p.dc_civac(uat.gpu_region, uat.NUM_CONTEXTS * 16)

    ascs = create_coprocessors(uat, args.verbose_asc)
    asc = ascs[0]
    if not args.build_before_start:
        print("Starting the coprocessors")
        start_coprocessors(ascs, args.verbose_asc)
    timing("power and start coprocessors")
    started_at = time.time()

    if args.restart_immediately:
        # A control for the restart-after-build result. If a stop and restart fails here, with
        # nothing built and the world untouched, then it fails for reasons of its own and the
        # restart-after-build failure says nothing about the world this path constructs.
        print("Restarting the coprocessors immediately, with nothing built")
        for instance in ascs:
            instance.stop()
            instance.add_ep(0, ManagementEndpoint(instance, 0))
        for path, instance in zip(g17p.COPROCESSOR_NODES[:len(ascs)], ascs):
            instance.boot()
            instance.mgmt.wait_boot(3)
            print("  %s running again" % path)
        print("  a stopped coprocessor can be restarted")

    bootstrap_high_root = (
        native_table_targets("firmware_high")[()]
        if SOURCE_NATIVE_PHYSICAL_TOPOLOGY
        else os.getenv("G17P_BOOTSTRAP_HIGH_ROOT_PA")
    )
    if bootstrap_high_root:
        target = (int(bootstrap_high_root, 0)
                  if isinstance(bootstrap_high_root, str)
                  else int(bootstrap_high_root))
        if target & (PAGE - 1):
            raise RuntimeError(
                "bootstrap high UAT root is not page aligned: %#x" % target)
        if target == uat.ttbr0_base:
            raise RuntimeError(
                "bootstrap high UAT root aliases the low root")
        original = uat.ttbr1_base
        # Each firmware instance has its own top table at the same relative
        # offset in its half of the shared region.  Preserve both live source
        # tables at the new physical base; mirror_secondary_top_table() will
        # later add the host mappings above their instance-private entries.
        for delta in (0, g17p.SECONDARY_SHARED_DELTA):
            body = iface.readmem(original + delta, PAGE)
            iface.writemem(target + delta, body)
            p.dc_civac(target + delta, PAGE)
            if iface.readmem(target + delta, PAGE) != body:
                raise RuntimeError(
                    "bootstrap high UAT root did not read back at %#x" %
                    (target + delta))
        uat.ttbr1_base = target
        uat.invalidate_cache()
        uat.invalidate_root_walk_cache()
        print(
            "  copied the live source firmware root to prescribed physical "
            "%#x (shared root was %#x)" % (target, original),
            flush=True,
        )

    uat.handoff = AbsentHandoff()

    print("Building an address space of our own from va %#018x" % kern_va_base)
    root_before = sample_shared_root(uat, "after the coprocessors started")
    bind_contexts(uat, args.macos_context_table)
    timing("initialize UAT roots")
    root_after = sample_shared_root(uat, "after this path initialised the tables")
    lost = sorted(set(root_before) - set(root_after))
    if lost:
        print("  DESTROYED %d entries firmware had published: %s"
              % (len(lost), ", ".join("[%d]=%#x" % (i, root_before[i]) for i in lost)))
    native_leaf_layout = None
    leaf_reference = os.getenv("G17P_BOOTSTRAP_LEAF_REFERENCE")
    if SOURCE_NATIVE_PHYSICAL_TOPOLOGY:
        native_leaf_layout = NativeLeafLayout.from_source(
            native_firmware_leaf_pages(), "firmware-high")
    elif leaf_reference:
        leaf_manifest_path = pathlib.Path(leaf_reference)
        if leaf_manifest_path.is_dir():
            leaf_manifest_path /= "manifest.json"
        leaf_manifest = json.loads(leaf_manifest_path.read_text())
        selected = leaf_manifest["selected_root"]
        high_groups = [
            group for group in leaf_manifest["root_mappings"]
            if int(group["root_index"]) == int(selected["index"])
            and int(group["root_ctx_id"]) == int(selected["ctx_id"])
            and int(group["selector"]) == 1
        ]
        if len(high_groups) != 1:
            raise RuntimeError(
                "bootstrap leaf reference has %d selected firmware-high "
                "roots" % len(high_groups))
        native_leaf_layout = NativeLeafLayout(
            leaf_manifest, high_groups[0], "firmware-high")
    arena = Arena(
        uat, CONTEXT, kern_va_base + g17p.NATIVE_HWDATA_OFFSET,
        native_layout=native_leaf_layout)
    built = build_initdata(arena, uat, kern_va_base, len(ascs))
    timing("build initdata")
    instances = built["instances"]
    names = {"hwdata", "data_region", "status_a", "private", "computed"}
    wanted = set() if args.graft == "none" else (
        names if args.graft == "all"
        else {value.strip() for value in args.graft.split(",") if value.strip()})
    if wanted - names:
        parser.error("unknown --graft region: %s" % sorted(wanted - names))
    grafted = graft_blank_initdata(arena, capture, built, instances, wanted)

    staged_control = stage_device_control(
        arena, capture, instances, args.opening,
        not args.empty_operand_table)
    timing("stage device control")
    render_state = build_render_context(arena, uat, capture, args.render_original_pa,
                                        args.render_payload_manifest)
    if OPENING_RENDER_STATE_HOOK[0] is not None:
        render_state = OPENING_RENDER_STATE_HOOK[0](
            render_state, arena, uat, capture)
        print("Applied the caller's opening render-state constructor", flush=True)
    timing("build render context")
    capture_pages_copied = sorted(render_state.get("capture_copied_vas") or ())
    if args.require_zero_capture_pages and capture_pages_copied:
        raise RuntimeError(
            "zero-capture-content assertion failed: copied render pages %s" %
            ", ".join("%#x" % va for va in capture_pages_copied))
    if args.require_zero_capture_pages:
        print("ZERO-CAPTURE-RENDER: PASS (0 complete render pages copied)")
    context_state = build_context_queue_state(arena, uat, capture,
                                              args.shared_control)
    tail_state = build_descriptor_tails(arena, uat, capture, render_state,
                                        context_state)
    timing("build context and tails")
    # Last of the mapping stages, so everything this path places itself is already in the arena and
    # is left alone; this only fills in the shape a host's firmware context has around it.
    firmware_extent = map_firmware_extent(arena, uat, capture,
                                         args.original_pa)
    if native_leaf_layout is not None:
        print(
            "  source constructors placed %d firmware-high pages at the "
            "native partial-render physical addresses" % arena.native_pages,
            flush=True,
        )
    timing("map firmware extent")
    # A working host's capture, trapped at its own first work doorbell, has the opening already
    # performed and its work published but **not** consumed: write pointer 3, done 0. This path
    # publishes before the control start, so firmware takes the group there and the doorbell finds
    # nothing left, which is the behaviour the record described as a property of the hardware.
    # Holding the producer back until after the control start reproduces a host's own ordering.
    deferred_producers = [] if args.publish_after_control else None
    prepared = prepare_work_group(arena, asc, capture, instances[0]["root_va"],
                                  render_state, context_state, tail_state,
                                  not args.no_place_submission,
                                  not args.no_announce,
                                  deferred_producers,
                                  ({v.strip() for v in args.defer_channel.split(",")}
                                   if args.defer_channel else None))
    timing("prepare work group")

    if args.second_group_early:
        prepared["ascs"] = ascs
        prepared["arena"] = arena
        prepared["uat"] = uat
        prepared["capture"] = capture
        prepared["instances"] = instances
        prepared["second_witness"] = {
            record["name"]: record["pa"] for record in render_state["pages"]
        }
        prepared["render_pages"] = render_state["pages"]
        prepared["context_state"] = context_state
        prepared["render_extent"] = render_state["extent"]["mapped"]
        prepared["render_bodies"] = render_state.get("bodies") or {}
        prepared["render_seeded_vas"] = render_state.get("seeded_vas") or set()
        submit_second_group(prepared, ring_now=False)

    context_zero = None
    if not args.no_context_zero:
        print("Building the %s contexts this path does not already provide" % (
            "source-described"
            if isinstance(capture, G17PSourceTopology) else "captured"))
        low_aliases = dict(built["primary_region_aliases"])
        low_aliases.update(prepared["low_aliases"])
        context_zero = build_captured_contexts(
            arena, uat, capture, render_state, low_aliases)
        if PARTIAL_OPENING_GRAPH:
            # Context 0 needs generated queue/context bodies at these low
            # addresses, but the clean render root has independent blank
            # backing at the same DVAs.  Copying context 0 above must happen
            # first; then restore the render-only pages to their native state.
            cleared = 0
            for kind in ("tiling", "fragment"):
                for page_pa in context_state["pages"][kind]["low_pas"]:
                    p.memset32(page_pa, 0, PAGE)
                    p.dc_civac(page_pa, PAGE)
                    cleared += 1
            print(
                "  clean partial render root: cleared %d independent "
                "queue/context pages after context-0 copy" % cleared,
                flush=True,
            )

    uat.flush_dirty()
    table_reference = os.getenv("G17P_BOOTSTRAP_TABLE_REFERENCE")
    context0_targets = low_targets = high_targets = None
    if SOURCE_NATIVE_PHYSICAL_TOPOLOGY:
        context0_targets = native_table_targets("context0")
        low_targets = native_table_targets("render_low")
        high_targets = native_table_targets("firmware_high")
    elif table_reference:
        manifest_path = pathlib.Path(table_reference)
        if manifest_path.is_dir():
            manifest_path /= "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        low_groups = [
            group for group in manifest["root_mappings"]
            if int(group["root_index"]) == NATIVE_RENDER_SLOT
            and int(group["root_ctx_id"]) == NATIVE_RENDER_CONTEXT
            and int(group["selector"]) == 0
        ]
        context0_groups = [
            group for group in manifest["root_mappings"]
            if int(group["root_index"]) == 0
            and int(group["root_ctx_id"]) == 0
            and int(group["selector"]) == 0
        ]
        selected = manifest["selected_root"]
        high_groups = [
            group for group in manifest["root_mappings"]
            if int(group["root_index"]) == int(selected["index"])
            and int(group["root_ctx_id"]) == int(selected["ctx_id"])
            and int(group["selector"]) == 1
        ]
        if (len(context0_groups) != 1 or len(low_groups) != 1
                or len(high_groups) != 1):
            raise RuntimeError(
                "bootstrap table reference has %d context-0, %d render-low "
                "slot-%d/context-%d, and %d firmware-high roots" % (
                    len(context0_groups), len(low_groups),
                    NATIVE_RENDER_SLOT, NATIVE_RENDER_CONTEXT,
                    len(high_groups)))
        context0_targets = native_table_topology(
            manifest, context0_groups[0])
        low_targets = native_table_topology(manifest, low_groups[0])
        high_targets = native_table_topology(manifest, high_groups[0])
    if low_targets is not None:
        if uat.ttbr0_base != low_targets[()]:
            raise RuntimeError(
                "bootstrap low root %#x does not match native target %#x" %
                (uat.ttbr0_base, low_targets[()]))
        if uat.ttbr1_base != high_targets[()]:
            raise RuntimeError(
                "bootstrap high root %#x does not match native target %#x" %
                (uat.ttbr1_base, high_targets[()]))
        uat.ttbr0_base = rebase_source_table_tree(
            uat, uat.ttbr0_base, low_targets, "render-low")
        uat.ttbr1_base = rebase_source_table_tree(
            uat, uat.ttbr1_base, high_targets, "firmware-high")
        if not context_zero or len(context_zero) != 1:
            raise RuntimeError(
                "native table placement requires one built context-0 root")
        context0_root = rebase_source_table_tree(
            uat, context_zero[0]["root"], context0_targets, "context-0")
        context_zero[0]["root"] = context0_root
        uat.set_l0(0, 0, context0_root, 0)
        u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
    mirror_secondary_top_table(uat)
    if args.split_context == "before":
        apply_context_split(uat)
    else:
        # Both roots stay on both slots through the opening, which is what the parameter-buffer
        # binding needs. The `0x20` entry's `+0x1c` names the operand table at a low address, and
        # with the split already applied firmware cannot translate the address its own entry names:
        # it consumes the entry and declines to act, and no binding happens. Measured both ways,
        # including with context 0 carrying the low root, which does not substitute for it.
        print("Both roots on both slots: firmware can translate the operand table it is given")
    uat.flush_dirty()
    uat.invalidate_cache()
    timing("publish UAT")

    if args.build_before_start:
        # Everything the coprocessors will be handed now exists, which is the order the replay path
        # has: it restores its world and only then starts the cores.
        print("Starting the coprocessors, with everything already built")
        start_coprocessors(ascs, args.verbose_asc)

    if args.restart_after_build:
        # Put the work on the other side of the boundary the record's rule names. A replay restores
        # its world and only then starts the cores, so its work is present before firmware runs an
        # instruction; this path stages after the cores are already running. Building everything and
        # then restarting the cores reaches the same ordering without building before the first start,
        # which hangs.
        print("Restarting the coprocessors with everything already in memory")
        # The first boot sees only slots 0, 1 and 7 populated. By now every captured context has its
        # own table, so a restart presents firmware with a root table it never sees at a cold start.
        # Clearing the extras across the restart separates that from the rest of the world.
        for index in range(uat.NUM_CONTEXTS):
            if index in (0, NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT):
                continue
            p.write64(uat.gpu_region + index * 16, 0)
            p.write64(uat.gpu_region + index * 16 + 8, 0)
        p.dc_civac(uat.gpu_region, uat.NUM_CONTEXTS * 16)
        for instance in ascs:
            instance.stop()
            # stop() resets the endpoint map and installs a stock management endpoint; this path
            # needs its own ordering back.
            instance.add_ep(0, ManagementEndpoint(instance, 0))
        for path, instance in zip(g17p.COPROCESSOR_NODES[:len(ascs)], ascs):
            instance.boot()
            instance.mgmt.wait_boot(3)
            print("  %s running again" % path)
        # Put the extra contexts back now that firmware has started.
        if not args.no_context_zero:
            low_aliases = dict(built["primary_region_aliases"])
            low_aliases.update(prepared["low_aliases"])
            build_captured_contexts(
                arena, uat, capture, render_state, low_aliases)

    if PARTIAL_OPENING_GRAPH:
        render_firmware_aliases = apply_render_firmware_aliases(
            uat, PARTIAL_OPENING_RENDER_FIRMWARE_ALIASES, capture,
            RENDER_SNAPSHOT_ROOT, prefer_low=True, arena=arena)
    elif legacy_aug5_topology():
        # This pass was introduced by the August 12 topology repair.  The
        # already-proven August 5 lifecycle had no such late aliases.
        render_firmware_aliases = []
        print("  legacy August 5 topology: skipped render/firmware alias pass",
              flush=True)
    else:
        render_firmware_aliases = apply_render_firmware_aliases(uat)

    separated_blank_pages = (
        separate_native_blank_pages(uat, capture)
        if args.separate_blank_pages else [])

    if args.dump_pages:
        dump_firmware_pages(
            uat, capture, pathlib.Path(args.dump_pages), instances,
            include_channel_state=args.dump_include_channel_state)

    deferred_fill = []
    if args.skip_input_completeness:
        completeness = {"skipped": True}
        print("Skipping the diagnostic input-completeness scan")
    else:
        completeness = report_input_completeness(
            arena, uat, capture,
            scan_blank=(args.scan_blank or args.blank_like_host),
            blank_like_host=args.blank_like_host,
            separate_blank=False,
            blank_only=({int(v, 16) for v in
                         args.blank_only.split(",") if v.strip()}
                        if args.blank_only else None),
            fill=args.fill_missing_input,
            defer=deferred_fill if args.fill_after_control else None,
            fill_bytes=({int(v, 16) for v in
                         args.fill_bytes.split(",") if v.strip()}
                        if args.fill_bytes else None),
            fill_only=({int(v, 16) for v in
                        args.fill_only.split(",") if v.strip()}
                       if args.fill_only else None))

    if args.opening == "done" and not PARTIAL_OPENING_GRAPH:
        # Applied here rather than while staging, because the shared control object is built after
        # the rings are staged and would overwrite it. The counters alone are not the after state,
        # though this option's help has long said they are: a world that has performed the opening
        # also has this object advanced, and the pre-work capture already does.
        cursor_pa = arena.physical(SHARED_CONTROL_ADDRESS)
        inner_pa = arena.physical(SHARED_CONTROL_INNER_ADDRESS)
        if cursor_pa is not None:
            iface.writemem(cursor_pa + SHARED_CONTROL_COUNT_AT,
                           struct.pack("<I", SHARED_CONTROL_COUNT_AFTER))
            p.dc_civac(cursor_pa & ~(PAGE - 1), PAGE)
        if inner_pa is not None:
            iface.writemem(inner_pa, bytes([SHARED_CONTROL_INNER_AFTER]))
            p.dc_civac(inner_pa & ~(PAGE - 1), PAGE)
        u.inst("dsb sy")
        print("Shared control object presented in its after state: cursor %#x, inner byte %d"
              % (SHARED_CONTROL_COUNT_AFTER, SHARED_CONTROL_INNER_AFTER))
    elif args.opening == "done":
        # `--opening done` also presents the device-control counters as
        # consumed.  Its historical object writes, however, target the old
        # c0830000/c1608000 generic shared-control pair.  In the clean partial
        # topology those DVAs are pool B and the TA status alias.  The
        # final-26.6 constructor below owns the real partial control at
        # c0828000/c1600000, so do not corrupt two unrelated objects here.
        print(
            "Partial opening leaves legacy shared-control object writes "
            "disabled; final-26.6 owns c0828000/c1600000",
            flush=True,
        )

    if args.premap_added:
        # A first submission adds 32 pages to the firmware context in a working world, and the
        # descriptor fields that come to name them are null until it does. If firmware has to create
        # them and cannot, a null is what it would be left holding. Pre-create them blank so it does
        # not have to.
        created = seeded = 0
        for line in pathlib.Path(args.premap_added).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            ctx_text, va_text = line.split()
            # Any context. The render slot and the firmware slot point at the same pair of tables
            # here, so one mapping serves both, and a list may name pages in either.
            del ctx_text
            va = int(va_text, 16)
            if leaf_output(uat, NATIVE_FIRMWARE_SLOT, va) is not None:
                continue
            fresh = u.memalign(PAGE, PAGE)
            p.memset32(fresh, 0, PAGE)
            if args.premap_content:
                # Blank pages are not enough: firmware follows the pointers into them and reads a
                # zero where a type is required, which is what "Invalid DataMaster 0" reports. Give
                # them the content a world that has run a submission has.
                body = pathlib.Path(args.premap_content) / ("%x.bin" % va)
                if body.exists():
                    iface.writemem(fresh, body.read_bytes()[:PAGE])
                    p.dc_civac(fresh, PAGE)
                    seeded += 1
            uat.iomap_at(CONTEXT, va, fresh, PAGE, **NORMAL_OBJECT_FLAGS)
            created += 1
        uat.flush_dirty()
        uat.invalidate_cache()
        u.inst("dsb sy")
        print("Pre-created %d firmware pages a first submission adds, %d with content"
              % (created, seeded))

    if args.apply_null_pointers:
        # Forty fields in the firmware context are null when a working host rings its first work
        # doorbell and hold device addresses by its second, so firmware fills them as a submission
        # runs. This path faults writing through a null while running one. Fill them in advance and
        # see whether the fault is one of these.
        applied = missing = 0
        for line in pathlib.Path(args.apply_null_pointers).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            va_text, off_text, value_text = line.split()
            va = int(va_text, 16)
            offset = int(off_text, 16)
            value = int(value_text, 16)
            pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
            if pa is None:
                missing += 1
                continue
            iface.writemem(pa + offset, struct.pack("<Q", value))
            p.dc_civac(pa & ~(PAGE - 1), PAGE)
            applied += 1
        u.inst("dsb sy")
        print("Pre-filled %d pointer fields a submission sets, %d pages not mapped here"
              % (applied, missing))

    if args.dump_pages_early:
        # Before the control start, which is where the first group dispatches. With the dump taken
        # just before the doorbell, the difference between them is what firmware does when it
        # dispatches, and that can be set against what it does when it declines.
        dump_firmware_pages(
            uat, capture, pathlib.Path(args.dump_pages_early), instances,
            include_channel_state=args.dump_include_channel_state)

    if args.build_dispatch:
        build_dispatch_record(uat)

    if args.build_records:
        build_per_submission_records(arena, uat, [
            ("tiling", SUBMISSION_ADDRESSES["work_descriptor_0"][0],
             SUBMISSION_ADDRESSES["queue_record_array"]),
            ("fragment", SUBMISSION_ADDRESSES["work_descriptor_0"][1],
             SUBMISSION_ADDRESSES["queue_record_array"] + g17p.QUEUE_RECORD_STRIDE),
        ])

    if args.apply_delta:
        # Everything a first submission changes in the firmware context, written in before the
        # control start. Not what a host does; a probe to see how far firmware gets when it is
        # handed the state it would have produced.
        applied = missing = 0
        delta_only = ({int(v, 16) for v in args.delta_only.split(",") if v.strip()}
                      if args.delta_only else None)
        delta_except = ({int(v, 16) for v in args.delta_except.split(",") if v.strip()}
                        if args.delta_except else set())
        # Grouped by page. Written one run at a time this was 4,898 proxy round trips and minutes
        # of wall clock; read-modify-write per page is a few dozen.
        wanted = {}
        for line in pathlib.Path(args.apply_delta).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            va_text, off_text, body_text = line.split()
            va = int(va_text, 16)
            if delta_only is not None and va not in delta_only:
                continue
            if va in delta_except:
                continue
            wanted.setdefault(va, []).append((int(off_text, 16),
                                              bytes.fromhex(body_text)))
        for va, runs in wanted.items():
            pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
            if pa is None:
                missing += 1
                continue
            page = bytearray(iface.readmem(pa, PAGE))
            for offset, body in runs:
                page[offset:offset + len(body)] = body
                applied += len(body)
            iface.writemem(pa, bytes(page))
            p.dc_civac(pa, PAGE)
        u.inst("dsb sy")
        print("Applied %d bytes of a first submission's firmware-context delta, %d runs unmapped"
              % (applied, missing))

    if args.graft_firmware_from:
        # Before the control start, not after it. Work executes at the control start when it is
        # already published, so a graft applied later cannot affect the run it is meant to test.
        graft_firmware_pages(arena, args.graft_firmware_from, args.graft_firmware_only)

    for spec in args.poke or []:
        # A named 32-bit field written before the control start. The dispatch record past the
        # operand inventory is a control field whose bits are not yet separated, and a poke is how
        # to separate them without giving the whole captured value each time.
        root, _, rest = spec.partition(":")
        where, _, what = rest.partition(":")
        root_index = int(root)
        dva = int(where, 16)
        value = int(what, 16)
        # Resolved through that context's own tables. An arena lookup knows nothing about contexts
        # and returns whichever object was mapped last at the address, which for an address mapped
        # in several contexts is the wrong page. That conflation has already been taken out of the
        # completeness measurement once and must not come back in through a probe.
        pa = leaf_output(uat, root_index, dva)
        if pa is None:
            raise SystemExit("poke target %#x is not mapped in root %d" % (dva, root_index))
        iface.writemem(pa, struct.pack("<I", value))
        p.dc_civac(pa & ~(PAGE - 1), PAGE)
        print("Poked root %d %#014x = %#010x at pa %#x" % (root_index, dva, value, pa))
    if args.poke:
        u.inst("dsb sy")

    if args.skip_leaf_audit:
        leaf_attrs = []
        print("Skipping the diagnostic capture-wide leaf-attribute scan")
    else:
        leaf_attrs = report_leaf_attributes(
            uat, capture, args.original_pa and args.render_original_pa)

    if FINAL_26_6_PRE_INIT_REGISTER_AUDIT is not None:
        FINAL_26_6_PRE_INIT_REGISTER_AUDIT("before", uat)
    p.write32(sgx_base + g17p.SGX_PRE_INIT_REGISTER, 0)
    if FINAL_26_6_PRE_INIT_REGISTER_AUDIT is not None:
        FINAL_26_6_PRE_INIT_REGISTER_AUDIT("after", uat)
    apply_scalars(arena, instances)
    prepare_final_26_6_opening_control(arena)

    # Queue ownership/identity is already stable in the clean pre-kick world;
    # it is not part of the producer transition.  Construct it while firmware
    # still has no initdata, so the early-state hook below can be the final
    # mutation of the TA-owned ring/event/optional ranges.
    if PARTIAL_OPENING_GRAPH:
        apply_native_partial_opening_queue(prepared)

    # The clean first-partial lifecycle presents only the fragment half while
    # initdata starts.  Deferring the channel producer is insufficient:
    # firmware also discovers a fully populated TA queue directly at startup.
    # Install the six measured early-state ranges after every ordinary
    # pre-init constructor (some of which writes the shared-control page), and
    # retain their generated later bytes for the 3D -> TA publication boundary.
    first_work_restore_later_state = None
    if (PARTIAL_OPENING_GRAPH
            and FINAL_26_6_FIRST_WORK_EARLY_STATE is not None):
        first_work_restore_later_state = (
            FINAL_26_6_FIRST_WORK_EARLY_STATE(prepared))
        if not callable(first_work_restore_later_state):
            raise RuntimeError(
                "first-work early-state hook did not return a restore callback")
    timing("pre-init diagnostics")

    # How long firmware has been running with nothing to do. The replay path restores its world and
    # hands over a descriptor promptly; this path builds a world over the proxy first, and whether
    # firmware degrades across that window is a question the record raised and closed at 90 seconds
    # without this number being known.
    idle = time.time() - started_at
    print("Firmware has been running %.1f s since the cores started, with no descriptor" % idle)

    for instance, entry in zip(ascs, instances):
        # Where a working host starts the two graphics endpoints: after the descriptor objects are
        # built, immediately before handing the descriptor over.
        instance.start_ep(0x20)
        instance.start_ep(0x21)
        message = InitMsg(TYPE=g17p.MSG_INITDATA,
                          INITDATA=entry["root_va"] & ((1 << 44) - 1))
        print("Sending initdata to %s: %#x" % (entry["name"], int(message.value)))
        instance.fw.send(message)

    deadline = time.time() + args.timeout
    crashed = {}
    while time.time() < deadline and not all(i.fw.acked for i in ascs):
        for instance, entry in zip(ascs, instances):
            if entry["name"] in crashed:
                continue
            try:
                instance.work_pending()
            except Exception as exc:
                # Say which instance died; both are polled here, so an unlabelled crash report
                # cannot be attributed to either one.
                crashed[entry["name"]] = str(exc)
                print("  %s CRASHED: %s" % (entry["name"], exc))
        if len(crashed) == len(ascs):
            break
        time.sleep(0.05)
    for instance, entry in zip(ascs, instances):
        print("  %s: %s" % (entry["name"],
                            "acknowledged" if instance.fw.acked else "no reply"))
    acked = all(i.fw.acked for i in ascs)
    print("RESULT: %s" % ("acknowledged" if acked else "no acknowledgement"))
    timing("initdata acknowledgement")

    post_ack_events = None
    if acked and args.drain_post_ack:
        before = [instance.fw.events for instance in ascs]
        deadline = time.time() + 0.01
        while time.time() < deadline:
            for instance, entry in zip(ascs, instances):
                if entry["name"] in crashed:
                    continue
                try:
                    instance.work_pending()
                except Exception as exc:
                    crashed[entry["name"]] = str(exc)
                    print("  %s CRASHED during post-ack drain: %s"
                          % (entry["name"], exc))
            if ascs[1].fw.events != before[1]:
                break
            time.sleep(0.001)
        after = [instance.fw.events for instance in ascs]
        post_ack_events = {
            entry["name"]: {"before": before[index], "after": after[index]}
            for index, entry in enumerate(instances)
        }
        print("  post-ack events before control: %s"
              % ", ".join("%s=%d->%d" % (
                  entry["name"], before[index], after[index])
                  for index, entry in enumerate(instances)))

    def control_counters(entry):
        values = []
        for pa in entry["channel_state_pas"][g17p.CHANNEL_TABLE_WORK_COUNT]:
            if not pa:
                values.append(0)
                continue
            p.dc_civac(pa, 4)
            values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    control_crashed = {}
    opening_counters = {}
    native_control_events = None
    control_done_sent_early = 0
    final_26_6_control = (
        os.getenv("G17P_FINAL_26_6_CONTROL_LIFECYCLE") == "1")
    present_primary_control_done = (
        os.getenv("G17P_SOURCE_PRESENT_PRIMARY_CONTROL_DONE") == "1")
    final_26_6_secondary = (
        os.getenv("G17P_FINAL_26_6_SECONDARY_LIFECYCLE") == "1")
    measured_control_lifecycle = (
        final_26_6_control or final_26_6_secondary)
    final_26_6_control_result = None
    context_split_applied_early = False

    def drain_native_event_barrier():
        targets = (1, 8)
        polls = 0
        for polls in range(1, 17):
            for instance, entry in zip(ascs, instances):
                if entry["name"] in control_crashed:
                    continue
                try:
                    instance.work_pending()
                except Exception as exc:
                    control_crashed[entry["name"]] = str(exc)
                    print("  %s CRASHED while draining native control events: %s"
                          % (entry["name"], exc))
            if all(instance.fw.events >= target
                   for instance, target in zip(ascs, targets)):
                break
            time.sleep(0.001)
        result = {
            entry["name"]: {
                "events": ascs[index].fw.events,
                "target": targets[index],
                "polls": polls,
            }
            for index, entry in enumerate(instances)
        }
        print("  native pre-work event barrier after %d polls: %s"
              % (polls,
                 ", ".join("%s=%d/%d" % (
                     entry["name"], ascs[index].fw.events, targets[index])
                     for index, entry in enumerate(instances))))
        return result

    if acked and FINAL_26_6_PRE_CONTROL_AUDIT is not None:
        FINAL_26_6_PRE_CONTROL_AUDIT({
            "arena": arena,
            "capture": capture,
            "instances": instances,
            "prepared": prepared,
            "uat": uat,
        })

    if acked:
        for position, index in enumerate(CONTROL_START_ORDER):
            ascs[index].db.send(DoorbellMsg(TYPE=g17p.MSG_CONTROL_START,
                                            CHANNEL=g17p.CONTROL_START_CHANNEL))
            if position + 1 < len(CONTROL_START_ORDER):
                time.sleep(CONTROL_START_GAP_MS / 1000.0)
        if measured_control_lifecycle:
            first_work_callback = None
            if (os.getenv("G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE") == "1"
                    and FINAL_26_6_FIRST_WORK is None):
                def first_work_callback(_ascs):
                    nonlocal context_split_applied_early
                    if deferred_producers is None:
                        raise RuntimeError(
                            "native first work has no deferred producers")
                    if not PARTIAL_OPENING_GRAPH:
                        apply_native_partial_opening_queue(prepared)
                    # Publication-boundary diagnostics need the instance
                    # inventory to omit live channel-counter pages from a
                    # content snapshot.  Keep it on the prepared state rather
                    # than adding another callback signature.
                    prepared["instances"] = instances
                    if FINAL_26_6_FIRST_WORK_PREPARE is not None:
                        FINAL_26_6_FIRST_WORK_PREPARE()
                    if FINAL_26_6_FIRST_WORK_AUDIT is not None:
                        FINAL_26_6_FIRST_WORK_AUDIT(prepared)
                    restore_later_state = first_work_restore_later_state
                    if (restore_later_state is None
                            and FINAL_26_6_FIRST_WORK_EARLY_STATE is not None):
                        restore_later_state = (
                            FINAL_26_6_FIRST_WORK_EARLY_STATE(prepared))
                        if not callable(restore_later_state):
                            raise RuntimeError(
                                "first-work early-state hook did not return "
                                "a restore callback")
                    if (PARTIAL_OPENING_GRAPH
                            and args.split_context == "after"):
                        # This callback runs inside the final-26.6 control
                        # lifecycle, at the captured 0x84 -> first 0x83
                        # boundary.  Waiting for the outer control routine to
                        # return applies the split only after the work has
                        # already retired.  Native removes the firmware low
                        # root here, after opcode 0x20 has bound the operand
                        # state and before either work producer is visible.
                        apply_context_split(uat)
                        context_split_applied_early = True
                    count = len(deferred_producers)
                    producer_writes = list(deferred_producers)
                    if PARTIAL_OPENING_GRAPH:
                        # Native constructs/publishes fragment before tiling;
                        # prepare_work_group stages them in TA,3D order.
                        producer_writes.reverse()
                    work_channel = (
                        FIRST_CHANNEL_PAIR[0] * 4
                        if PARTIAL_OPENING_GRAPH else 0)
                    if PARTIAL_OPENING_GRAPH:
                        # The targeted trace observes the 3D producer first
                        # and TA second, followed by one pair mailbox kick.
                        # Producer ordering is real, but there is no
                        # fragment-only execution interval: doorbelling each
                        # producer separately lets 3D retire before TA has
                        # emitted any tiles and also gives the scheduler a
                        # duplicate notification for the same pair.
                        for index, (address, value) in enumerate(
                                producer_writes):
                            if index == 1 and restore_later_state is not None:
                                restore_later_state()
                                u.inst("dsb sy")
                            prepared["submitter"].write(address, value)
                        u.inst("dsb sy")
                        ascs[0].db.send(DoorbellMsg(
                            TYPE=g17p.MSG_WORK_DOORBELL,
                            CHANNEL=work_channel))
                    else:
                        for address, value in producer_writes:
                            prepared["submitter"].write(address, value)
                        u.inst("dsb sy")
                        ascs[0].db.send(DoorbellMsg(
                            TYPE=g17p.MSG_WORK_DOORBELL,
                            CHANNEL=work_channel))
                    deferred_producers.clear()
                    prepared["submitter"].deferred_producers = None
                    print(
                        "  published %d source first-work producers in the "
                        "native control 0x84 -> work 0x83 interval%s, "
                        "%s on channel %#x" % (
                            count,
                            " (3D then TA)" if PARTIAL_OPENING_GRAPH else "",
                            ("one ordered-pair doorbell"
                             if PARTIAL_OPENING_GRAPH else "doorbell"),
                            work_channel),
                        flush=True,
                    )
                    return {"channel": 0, "published_producers": count}

            final_26_6_control_result = publish_final_26_6_control_lifecycle(
                instances, ascs,
                publish_primary=(final_26_6_control
                                 and not present_primary_control_done),
                first_work_callback=first_work_callback)
            control_done_sent_early = 1
            if (not final_26_6_control_result["retired"]
                    and (final_26_6_control
                         or FINAL_26_6_FIRST_WORK is not None)):
                raise RuntimeError(
                    "final-26.6 control lifecycle did not retire: %r" %
                    (final_26_6_control_result,))
            if not final_26_6_control_result["retired"]:
                print(
                    "  final-26.6 secondary controls remain pending for "
                    "the first real primary work doorbell",
                    flush=True,
                )
        elif args.native_mailbox_order:
            for _ in range(args.control_done_before_doorbell):
                asc.db.send(GpuMsg(0x0084000000000011))
            control_done_sent_early = args.control_done_before_doorbell
            if control_done_sent_early:
                print("  sent %d control-done before reading control events, as macOS does"
                      % control_done_sent_early)
            native_control_events = drain_native_event_barrier()
        else:
            for _ in range(10):
                # A control-start message sent to one instance can make the other emit its crash
                # notification, so poll both rather than stopping before the result is written.
                for instance, entry in zip(ascs, instances):
                    if entry["name"] in control_crashed:
                        continue
                    try:
                        instance.work_pending()
                    except Exception as exc:
                        control_crashed[entry["name"]] = str(exc)
                        print("  %s CRASHED during control start: %s"
                              % (entry["name"], exc))
                time.sleep(0.001)
        print("  control start sent to %d instances" % len(CONTROL_START_ORDER))
        if args.publish_after_control and deferred_producers:
            for address, value in deferred_producers:
                prepared["submitter"].write(address, value)
            u.inst("dsb sy")
            print("  published %d held-back channel producers, after the control start as a host "
                  "does" % len(deferred_producers))
            deferred_producers.clear()
            # Stop deferring. Clearing the list leaves it non-None, and the submitter defers on
            # "is not None", so every later group's producer write went on being appended to a list
            # nobody publishes again. A second group staged after this point advanced its queue's
            # write index and its ring slot but never its channel producer, which is the one thing
            # that tells firmware to look.
            prepared["submitter"].deferred_producers = None
            if args.records_after_publish:
                # The records name the group, so a host submitting into a running world would write
                # them after publishing rather than before. Worth trying on the route where the
                # group is published after the control start and nothing runs.
                build_per_submission_records(arena, uat, [
                    ("tiling", SUBMISSION_ADDRESSES["work_descriptor_0"][0],
                     SUBMISSION_ADDRESSES["queue_record_array"]),
                    ("fragment", SUBMISSION_ADDRESSES["work_descriptor_0"][1],
                     SUBMISSION_ADDRESSES["queue_record_array"] + g17p.QUEUE_RECORD_STRIDE),
                ])
            if args.second_control_start:
                # A group visible when the opening completes is executed; the same group published
                # afterwards is consumed at its doorbell and not executed. If a second control
                # start runs it, then what makes firmware execute is that notification and not the
                # doorbell, which is worth knowing before anything else is tried.
                for index in CONTROL_START_ORDER:
                    ascs[index].db.send(DoorbellMsg(
                        TYPE=g17p.MSG_CONTROL_START,
                        CHANNEL=g17p.CONTROL_START_CHANNEL))
                    time.sleep(CONTROL_START_GAP_MS / 1000.0)
                print("  sent a second control start, after publishing")
        counter_deadline = time.time() + 0.02
        expected_opening_counters = (
            {entry["name"]: tuple(
                final_26_6_control_result["target"][index])
             for index, entry in enumerate(instances)}
            if measured_control_lifecycle else
            {entry["name"]: (1, 1, 1) for entry in instances})
        while time.time() < counter_deadline:
            opening_counters = {entry["name"]: control_counters(entry)
                                for entry in instances}
            if opening_counters == expected_opening_counters:
                break
            time.sleep(0.001)
        print("  opening control counters: %s"
              % ", ".join("%s=%s" % (name, values)
                          for name, values in opening_counters.items()))

    # When the work is taken. A replay's work is consumed during the initial control start, before
    # any work doorbell, because it is already on the rings when firmware comes up. If this path's is
    # only taken at the doorbell then the two are being serviced by different paths inside firmware,
    # which no comparison of content could show.
    for name in sorted(prepared["staged"]):
        entry = prepared["channels"].by_name(name)
        now = [struct.unpack("<I", prepared["read"](addr, 4))[0]
               for addr in entry["state_addrs"][:3]]
        print("  %s counters after the control start, before any doorbell: %s -> %s  %s"
              % (name, prepared["counters_before"][name], now,
                 "taken at startup" if now[:2] != prepared["counters_before"][name][:2]
                 else "not yet taken"))

    opening_effect = read_opening_effect(arena, "after the control start")
    announced = None
    if (acked and not measured_control_lifecycle
            and not opening_effect["_advanced"]):
        # The staged opening was consumed without being acted on. Publish the same `0x20` again on
        # the running instance, announced the way a host announces every entry, and look again.
        print("Re-publishing the 0x20 on the running primary, announced")
        announced = announce_control_entry(instances[0], asc,
                                           build_control_20_entry(),
                                           "announced 0x20")
        opening_effect = read_opening_effect(arena, "after the announced 0x20")

    if (args.split_context == "after"
            and not context_split_applied_early):
        # The capture's steady state has no low root on the firmware slot, and the binding needs one.
        # Both hold if a host binds while it is present and removes it afterwards, which is what this
        # does: the opening has been processed by now, so the split lands between the binding and the
        # work.
        apply_context_split(uat)

    control_done_remaining = max(
        0, args.control_done_before_doorbell - control_done_sent_early)
    for _ in range(control_done_remaining):
        # What macOS sends here, from its own trapped mailbox sequence: after the control start and
        # before the first work doorbell it writes one 0x84 with this payload. This path went
        # straight from the control start to the doorbell. Its trace contains no 0x87 at this point,
        # so the earlier interleave test included a message a host does not send here.
        asc.db.send(GpuMsg(0x0084000000000011))
    if control_done_remaining:
        print("  sent %d control-done before the doorbell, as macOS does"
              % control_done_remaining)

    if args.drain_native_control_events and native_control_events is None:
        native_control_events = drain_native_event_barrier()

    if args.dump_pages_late:
        # The early dump runs before firmware has ever seen this world. Comparing it against a
        # capture taken at the work doorbell compares a host's inputs against a world firmware has
        # already initialised, so a firmware write shows up as a difference in inputs. Dumping again
        # here, at the same point in the sequence the capture was triggered, makes the two
        # comparable and shows what firmware itself left different.
        dump_firmware_pages(
            uat, capture, pathlib.Path(args.dump_pages_late), instances,
            include_channel_state=args.dump_include_channel_state)

    if args.fill_after_control:
        apply_deferred_fill(deferred_fill)

    native_overlay = None
    if args.native_firmware_overlay_late:
        # This is deliberately the last memory write before the doorbell. Applying native state
        # before the control start lets firmware immediately replace it and does not test an exact
        # replay of the captured boundary.
        native_overlay = graft_native_firmware_pages(
            uat, capture, args.native_firmware_overlay_only)

    registers_before = sample_accelerator_registers()
    if args.pre_work_interleave:
        # A booted host interleaves these with its work continuously, from the opening onward, and
        # this path sent the opening and then nothing but the work doorbell. Measured: it changes
        # nothing, and a rendering replay's own mailbox trace contains neither message, so they are
        # not required for a first submission. Kept because a host does send them.
        for _ in range(args.pre_work_interleave):
            asc.db.send(GpuMsg(0x0087000000000010))
            asc.db.send(GpuMsg(0x0084000000000011))
        print("Interleaved %d rounds of 0x87 and 0x84 before the work doorbell"
              % args.pre_work_interleave)

    ticks = []
    if args.control_ticks:
        print("Publishing runtime device-control entries, as a booted host does per doorbell")
        for index in range(args.control_ticks):
            ticks.append(publish_control_tick(instances[0], asc, index))

    if args.second_group:
        prepared["ascs"] = ascs
        prepared["arena"] = arena
        prepared["uat"] = uat
        prepared["capture"] = capture
        prepared["instances"] = instances
        # The secondary's channel 14 is the only report channel that carries records here.
        secondary = instances[1]
        states, ring_va = secondary["channels"][14]
        producer_pa = arena.physical(states[0]) if states[0] else None
        ring_pa = arena.physical(ring_va) if ring_va else None
        if producer_pa and ring_pa:
            prepared["trace_channel"] = {"producer": producer_pa, "ring": ring_pa}
        prepared["second_witness"] = {
            record["name"]: record["pa"] for record in render_state["pages"]
        }
        prepared["render_pages"] = render_state["pages"]
        prepared["context_state"] = context_state
        prepared["render_extent"] = render_state["extent"]["mapped"]
        prepared["render_bodies"] = render_state.get("bodies") or {}
        prepared["render_seeded_vas"] = render_state.get("seeded_vas") or set()

    # Both instances and their mailboxes, available from the first publication onward rather than
    # only once a second group is being built.
    prepared.setdefault("instances", instances)
    prepared.setdefault("ascs", ascs)

    def device_control_counters(label):
        """Both instances' device-control counters, read straight from their channel state.

        A host's secondary consumes five control entries between its two work doorbells and nothing
        says whether the host or firmware published them. If firmware does it while dispatching,
        this path's own secondary should move here, during a dispatch that works.
        """
        for name, entry in (("primary", instances[0]), ("secondary", instances[1])):
            states = entry["channel_state_pas"][g17p.CHANNEL_TABLE_WORK_COUNT]
            values = []
            for pa in states[:3]:
                if not pa:
                    values.append(0)
                    continue
                p.dc_civac(pa, 8)
                values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
            print("  %-9s device control %s: %s" % (name, label, values))

    device_control_counters("before the work group")
    group_result = publish_work_group(
        prepared, immediate_second=args.second_group_immediate)
    device_control_counters("after the work group")
    second = group_result.pop("immediate_second", None)

    # A submission can be accepted, scheduled and retired without drawing, so let firmware run on
    # before reading the pages that say whether it drew.
    deadline = time.time() + 0.5
    while time.time() < deadline:
        with contextlib.suppress(Exception):
            asc.work_pending()
        time.sleep(0.01)
    registers = report_accelerator_registers(registers_before,
                                             sample_accelerator_registers())
    witness = read_render_witness(render_state)
    render_execution_pages = []
    for record in render_state["pages"]:
        values = witness.get(record["name"]) or {}
        if not values.get("differing"):
            continue
        p.dc_civac(record["pa"], PAGE)
        render_execution_pages.append({
            "name": record["name"],
            "dva": record["va"],
            "pa": record["pa"],
            "before": bytes(record["body"]),
            "after": bytes(iface.readmem(record["pa"], PAGE)),
        })
    if args.dump_pages_after:
        # What firmware did with the group, measured rather than inferred. A run that consumes and
        # retires without executing still touched something, and the difference between this and the
        # dump taken before the doorbell is the whole of it.
        dump_firmware_pages(
            uat, capture, pathlib.Path(args.dump_pages_after), instances,
            include_channel_state=args.dump_include_channel_state)

    if args.drain_reports:
        drain_report_channels(arena, instances)

    if args.second_group and second is None:
        second = submit_second_group(prepared)

    reports = read_report_channels(arena, instances, "after the work group")

    capture_write_bytes = sum(record["size"] for record in CAPTURE_WRITE_AUDIT)
    if args.require_zero_capture_pages and CAPTURE_WRITE_AUDIT:
        details = ", ".join(
            "%s@%#x:%#x" % (record["source"], record["address"], record["size"])
            for record in CAPTURE_WRITE_AUDIT[:12])
        if len(CAPTURE_WRITE_AUDIT) > 12:
            details += ", ..."
        raise RuntimeError(
            "global zero-capture assertion failed: %d writes/%#x bytes: %s" %
            (len(CAPTURE_WRITE_AUDIT), capture_write_bytes, details))
    if args.require_zero_capture_pages:
        if CAPTURE_READ_AUDIT:
            raise RuntimeError(
                "global zero-capture assertion failed: snapshot input opened: "
                + ", ".join(CAPTURE_READ_AUDIT))
        print("ZERO-CAPTURE-INPUT: PASS (no snapshot or trace closure opened)")
        print("ZERO-CAPTURE-CONTENT: PASS (0 captured writes, 0 captured bytes)")

    # The render records keep each page's seeded content so the witness can compare by content, and
    # bytes do not serialise. Drop it from the artifact rather than from the record.
    for record in render_state.get("pages", []):
        record.pop("body", None)

    # Everything G17PShimBackend needs to attach to the firmware this run started. Keep this as a
    # first-class value as well as serialising it: the embedded DRM shim cold-boots and consumes
    # this state in one process, so boot.json is a diagnostic artifact rather than an IPC layer.
    attach_state = {
        "initdata_addr": instances[0]["root_va"],
        "secondary_initdata_addr": instances[1]["root_va"],
        # The physical address of the initdata object itself, not a translation root. It is
        # recorded because a backend that cannot translate firmware addresses can at least read
        # the descriptor directly; the root a backend would need to walk is not this.
        "initdata_pa": instances[0].get("root_pa"),
        # Where each render page physically is. An attaching process reading these needs no
        # translation of its own, which is the part that has been getting the render extent
        # wrong: it can read the physical pages the accelerator wrote.
        # The eight values a DRM command buffer does not carry and the backend does not
        # derive: three deflake addresses and the auxiliary framebuffer, then the shared
        # record, the record pools and both optional records. The backend refuses without
        # them, deliberately, because a zero here publishes work that draws nothing.
        "submission_state": {
            "deflake_1": RENDER_PARAMETERS["deflake_1"],
            "deflake_2": RENDER_PARAMETERS["deflake_2"],
            "deflake_3": RENDER_PARAMETERS["deflake_3"],
            "aux_fb": RENDER_PARAMETERS["aux_fb"],
            # These source-built render objects survive the opening group. A
            # live frontend retains their addresses instead of allocating
            # replacement pages only because the public command omits them.
            "tilemap": RENDER_PARAMETERS["tilemap"],
            "tpc": RENDER_PARAMETERS["tpc"],
            "ta_status": RENDER_PARAMETERS["ta_status"],
            "fragment_status": RENDER_PARAMETERS["fragment_status"],
            # The backend reads this off the command buffer too, and neither a DRM buffer nor
            # the eight values above carry it. Without it the last thing between a client's
            # submission and this backend is still a hand-set value.
            "heapmeta": RENDER_PARAMETERS["heapmeta"],
            # The builder constructs the shared objects itself when this is null, which is
            # what the boot passes it. An address here is the descriptor shared object, which
            # is a different thing that the builder then tries to index.
            "shared": None,
            # Three values, not two: the builder takes both pool bases and the shared slot,
            # and passing only the pools failed late inside the publish path rather than being
            # refused by name.
            # Empty means the builder constructs its own pools, shared objects and leaf
            # pages, which is what the boot does through build_submission_graph.
            "pools": [],
            # The builder allocates the optional items itself; what it wants under these
            # names is the four-pointer set each kind's item is built from. Supplying the item
            # addresses instead matched the name in this record and not the one in the API,
            # and failed inside the builder rather than being refused.
            "tiling_optional": dict(context_state["pointers"]["tiling"]),
            "fragment_optional": dict(context_state["pointers"]["fragment"]),
        },
        # The staged opening group has already bound these objects by the time
        # a live frontend can append work. They are lifecycle state, not command
        # buffer inputs: later groups on this queue continue to use them.
        "bound_submission": {
            "pools": [SUBMISSION_ADDRESSES["record_pool_a"],
                      SUBMISSION_ADDRESSES["record_pool_b"]],
            "shared": [SUBMISSION_ADDRESSES["descriptor_shared_object"],
                       SUBMISSION_ADDRESSES["descriptor_zero_object"]],
            "leaf_pages": dict(LEAF_PAGE_ADDRESSES),
        },
        # Which of those pages carry the workload's own inputs. The rest are what the
        # accelerator writes, so a witness can clear the output without removing the input.
        "render_seeded": ["%#x" % va for va in sorted(render_state.get("seeded_vas") or ())],
        "render_capture_copied": [
            "%#x" % va for va in capture_pages_copied
        ],
        "capture_write_audit": list(CAPTURE_WRITE_AUDIT),
        "capture_read_audit": list(CAPTURE_READ_AUDIT),
        "render_written": ["%#x" % va for va in RENDER_WRITTEN_PAGES],
        "render_extent": {
            "%#x" % va: "%#x" % pa
            for va, pa in sorted(render_state["extent"]["mapped"].items())
        },
        "context": CONTEXT,
        "doorbell_type": g17p.MSG_WORK_DOORBELL,
        "doorbell_channel": 0,
    }

    (out / "boot.json").write_text(json.dumps({
        "attach": attach_state,
        "format": "m1n1-t8140-g17p-boot-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": None if args.require_zero_capture_pages else str(SNAPSHOT),
        "acknowledged": bool(acked),
        "crashed": crashed,
        "control_crashed": control_crashed,
        "opening_control_counters": {name: list(values)
                                     for name, values in opening_counters.items()},
        "events": asc.fw.events,
        "opening_effect": opening_effect,
        "post_ack_events": post_ack_events,
        "native_control_events": native_control_events,
        "native_mailbox_order": bool(args.native_mailbox_order),
        "staged_control": staged_control,
        "final_26_6_control_lifecycle": final_26_6_control_result,
        "announced_control_entry": announced,
        "report_channels": reports,
        "accelerator_registers": registers,
        "control_ticks": ticks,
        "idle_seconds_before_initdata": idle,
        "grafted_initdata": grafted,
        "seeded_regions": seeded_regions,
        "capture_write_audit": list(CAPTURE_WRITE_AUDIT),
        "capture_read_audit": list(CAPTURE_READ_AUDIT),
        "input_completeness": completeness,
        "leaf_attributes": leaf_attrs,
        "native_firmware_overlay": native_overlay,
        "render_firmware_aliases": render_firmware_aliases,
        "separated_blank_pages": separated_blank_pages,
        "context_zero": context_zero,
        "management_coprocessor": bool(smc),
        "shared_root_before": {str(k): v for k, v in root_before.items()},
        "shared_root_after": {str(k): v for k, v in root_after.items()},
        "work_group": group_result,
        "second_group": second,
        "firmware_extent": firmware_extent,
        "context_queue_pointers": {
            kind: {name: "%#x" % value for name, value in pointers.items()}
            for kind, pointers in context_state["pointers"].items()
        },
        "render_context": {
            "pages": render_state["pages"],
            "capture_pages_copied": len(capture_pages_copied),
            "tiling_writes": len(render_state["registers"]["tiling"]),
            "fragment_writes": len(render_state["registers"]["fragment"]),
            "witness": witness,
        },
        "kern_va_base": kern_va_base,
        "handoff_base": handoff_base,
        "root_va": instances[0]["root_va"],
        "register_windows": built["register_windows"],
        "allocations": arena.entries,
    }, indent=2, sort_keys=True) + "\n")
    print("Wrote %s" % (out / "boot.json"))
    if return_state:
        if not acked:
            raise RuntimeError("G17P cold boot did not acknowledge both initdata objects")

        runtime_control_sequence = [0]

        def announce_runtime_tick(
                counter, label="runtime 0x2e", require_consumed=True,
                context_word=0, update_sequence=False):
            """Publish one sequenced primary opcode-0x2e control entry."""
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<II", body, 0, 0x2e, int(counter))
            struct.pack_into("<I", body, 0x0c, int(context_word))
            result = announce_control_entry(
                instances[0], ascs[0], bytes(body), label)
            if require_consumed and not result["consumed"]:
                raise RuntimeError(
                    "firmware did not consume runtime control tick %d: %r" %
                    (counter, result))
            if update_sequence:
                runtime_control_sequence[0] = int(counter)
            return result

        def publish_runtime_tick(
                counter, label="runtime 0x2e", context_word=0,
                update_sequence=False):
            """Publish one primary tick and send one 0x84 without waiting."""
            instance = instances[0]
            asc = ascs[0]
            states = instance["channel_state_pas"][
                g17p.CHANNEL_TABLE_WORK_COUNT]

            def counters():
                values = []
                for address in states[:3]:
                    p.dc_civac(address, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(address, 4)))[0])
                return tuple(values)

            before = counters()
            producer = before[g17p.CHANNEL_STATE_PRODUCER]
            if producer >= g17p.RING_SLOT_COUNT:
                raise RuntimeError("primary control ring is full")
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<II", body, 0, 0x2e, int(counter))
            struct.pack_into("<I", body, 0x0c, int(context_word))
            address = (instance["control_ring_pa"]
                       + producer * g17p.CONTROL_MESSAGE_SIZE)
            iface.writemem(address, bytes(body))
            p.dc_civac(address, len(body))
            target = producer + 1
            p.write32(states[g17p.CHANNEL_STATE_PRODUCER], target)
            p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 4)
            u.inst("dsb sy")
            asc.db.send(DoorbellMsg(
                TYPE=g17p.MSG_CONTROL_DONE,
                CHANNEL=CONTROL_ANNOUNCE_PAYLOAD))
            after = counters()
            if update_sequence:
                runtime_control_sequence[0] = int(counter)
            print(
                "  %s at slot %d: %s -> %s; one 0x84, no retirement wait" %
                (label, producer, list(before), list(after)),
                flush=True,
            )
            return {
                "slot": producer,
                "target": target,
                "before": list(before),
                "after_send": list(after),
            }


        def stage_runtime_tick(
                counter, label="runtime 0x2e", context_word=0,
                update_sequence=False):
            """Publish one primary tick without sending a control doorbell."""
            instance = instances[0]
            states = instance["channel_state_pas"][
                g17p.CHANNEL_TABLE_WORK_COUNT]

            def counters():
                values = []
                for address in states[:3]:
                    p.dc_civac(address, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(address, 4)))[0])
                return tuple(values)

            before = counters()
            producer = before[g17p.CHANNEL_STATE_PRODUCER]
            if producer >= g17p.RING_SLOT_COUNT:
                raise RuntimeError("primary control ring is full")
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<II", body, 0, 0x2e, int(counter))
            struct.pack_into("<I", body, 0x0c, int(context_word))
            address = (instance["control_ring_pa"]
                       + producer * g17p.CONTROL_MESSAGE_SIZE)
            iface.writemem(address, bytes(body))
            p.dc_civac(address, len(body))
            target = producer + 1
            p.write32(states[g17p.CHANNEL_STATE_PRODUCER], target)
            p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 4)
            u.inst("dsb sy")
            after = counters()
            if update_sequence:
                runtime_control_sequence[0] = int(counter)
            print(
                "  %s at slot %d: %s -> %s; pending for next work kick" %
                (label, producer, list(before), list(after)),
                flush=True,
            )
            return {
                "slot": producer,
                "target": target,
                "before": list(before),
                "after_publish": list(after),
            }

        def stage_secondary_runtime_22(count=5):
            """Publish bare gfx1 opcode-0x22 records without a mailbox kick."""
            secondary = instances[1]
            states = secondary["channel_state_pas"][
                g17p.CHANNEL_TABLE_WORK_COUNT]

            def counters():
                values = []
                for address in states[:3]:
                    p.dc_civac(address, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(address, 4)))[0])
                return tuple(values)

            before = counters()
            producer = before[g17p.CHANNEL_STATE_PRODUCER]
            target = producer + int(count)
            if not 0 < int(count) or target > g17p.RING_SLOT_COUNT:
                raise ValueError(
                    "secondary runtime batch crosses its ring: %d..%d" %
                    (producer, target - 1))
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<I", body, 0, 0x22)
            for slot in range(producer, target):
                address = (secondary["control_ring_pa"]
                           + slot * g17p.CONTROL_MESSAGE_SIZE)
                iface.writemem(address, bytes(body))
                p.dc_civac(address, len(body))
            p.write32(states[g17p.CHANNEL_STATE_PRODUCER], target)
            p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 4)
            u.inst("dsb sy")
            after = counters()
            print(
                "  staged secondary runtime 0x22 slots %d..%d: %s -> %s; "
                "no secondary mailbox" %
                (producer, target - 1, list(before), list(after)),
                flush=True,
            )
            return {
                "before": list(before),
                "target": target,
                "after_publish": list(after),
            }

        def register_runtime_pair():
            """Perform the primary control transition seen before native pair one."""
            first_pages = capture.by_root[capture.selected_root]
            growth = None
            if os.getenv("G17P_RUNTIME_PAIR_GROWTH") == "1":
                mapped_blank = already = 0
                for va, attr_index, uxn in RUNTIME_PAIR_BLANK_PAGES:
                    current_pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
                    if current_pa is not None:
                        already += 1
                        continue
                    pa = u.memalign(PAGE, PAGE)
                    p.memset32(pa, 0, PAGE)
                    mapped_blank += 1
                    p.dc_civac(pa, PAGE)
                    uat.iomap_at(
                        CONTEXT, va, pa, PAGE,
                        AttrIndex=attr_index, AP=1, UXN=uxn,
                    )
                    arena.entries.append({
                        "name": "runtime_growth_%#x" % va,
                        "va": va,
                        "pa": pa,
                        "size": PAGE,
                    })
                uat.flush_dirty()
                uat.invalidate_cache()
                print(
                    "  runtime firmware growth: %d explicit blank pages, "
                    "%d already mapped" % (mapped_blank, already),
                    flush=True,
                )

            if os.getenv("G17P_RUNTIME_LOW_ROOT_GROWTH") == "1":
                mapped = already = 0
                for low_base, high_base, page_count in RUNTIME_PAIR_CONTEXT_ALIASES:
                    for index in range(page_count):
                        low = low_base + index * PAGE
                        high = high_base + index * PAGE
                        pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, high)
                        if pa is None:
                            raise RuntimeError(
                                "runtime queue context page %#x is unmapped" % high)
                        if leaf_output(uat, 0, low) == pa:
                            already += 1
                            continue
                        uat.iomap_at(
                            0, low, pa, PAGE, AttrIndex=MemoryAttr.Shared,
                            AP=2, nG=1, UXN=0, OS=1)
                        mapped += 1
                uat.flush_dirty()
                uat.invalidate_cache()
                u.inst("dsb sy")
                print(
                    "  runtime context-0 growth: %d explicit high aliases, "
                    "%d already mapped" % (mapped, already),
                    flush=True,
                )

            if os.getenv("G17P_RUNTIME_GLOBAL_TLBI") == "1":
                # Preserve the measured publication order, but rule out a stale
                # negative GMMU walk surviving the ordinary ASID invalidation.
                u.inst("dsb osh; tlbi vmalle1os; dsb osh; isb")
                print("  runtime global translation invalidation complete",
                      flush=True)

            def apply_runtime_host_delta():
                nonlocal growth
                if args.require_zero_capture_pages:
                    raise RuntimeError(
                        "runtime host-delta replay is forbidden by "
                        "--require-zero-capture-pages")
                if growth is None:
                    growth = Capture(SECOND_SNAPSHOT)
                later = growth.by_root[growth.selected_root]
                only_text = os.getenv("G17P_RUNTIME_PAIR_HOST_DELTA_ONLY", "")
                only = ({int(value, 0) & ~(PAGE - 1)
                         for value in only_text.split(",") if value.strip()}
                        if only_text else None)
                exclude_text = os.getenv(
                    "G17P_RUNTIME_PAIR_HOST_DELTA_EXCLUDE", "")
                exclude = {
                    int(value, 0) & ~(PAGE - 1)
                    for value in exclude_text.split(",") if value.strip()
                }
                pages = changed_bytes = 0
                for va, (later_index, _pte) in sorted(later.items()):
                    if (va not in first_pages
                            or (only is not None and va not in only)
                            or va in exclude):
                        continue
                    before = capture.blob(first_pages[va][0])
                    after = growth.blob(later_index)
                    if before == after:
                        continue
                    pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, va)
                    if pa is None:
                        raise RuntimeError(
                            "runtime host-delta page %#x is unmapped" % va)
                    p.dc_civac(pa, PAGE)
                    ours = bytearray(iface.readmem(pa, PAGE))
                    changed = 0
                    for offset, (old, new) in enumerate(zip(before, after)):
                        if old != new:
                            ours[offset] = new
                            changed += 1
                    iface.writemem(pa, ours)
                    p.dc_civac(pa, PAGE)
                    audit_capture_write("runtime-host-delta", va, changed)
                    pages += 1
                    changed_bytes += changed
                u.inst("dsb sy")
                print(
                    "  runtime first-to-second host delta: %d bytes over %d pages" %
                    (changed_bytes, pages),
                    flush=True,
                )

            secondary_mode = os.getenv("G17P_SECONDARY_RUNTIME_22", "").strip()
            secondary_state = None
            if secondary_mode:
                if secondary_mode not in ("publish", "complete"):
                    raise ValueError(
                        "G17P_SECONDARY_RUNTIME_22 must be publish or complete")
                secondary = instances[1]
                channel = g17p.CHANNEL_TABLE_WORK_COUNT
                states = secondary["channel_state_pas"][channel]

                def secondary_counters():
                    values = []
                    for pa in states[:3]:
                        if not pa:
                            values.append(0)
                            continue
                        p.dc_civac(pa, 4)
                        values.append(struct.unpack(
                            "<I", bytes(iface.readmem(pa, 4)))[0])
                    return tuple(values)

                before = secondary_counters()
                producer = before[g17p.CHANNEL_STATE_PRODUCER]
                body = bytearray(5 * g17p.CONTROL_MESSAGE_SIZE)
                for index in range(5):
                    struct.pack_into(
                        "<I", body, index * g17p.CONTROL_MESSAGE_SIZE, 0x22)
                ring = (secondary["control_ring_pa"]
                        + producer * g17p.CONTROL_MESSAGE_SIZE)
                iface.writemem(ring, bytes(body))
                p.dc_civac(ring, len(body))
                target = producer + 5
                if secondary_mode == "complete":
                    # A native stream is only observable after this transition and
                    # has all three counters at 21. This mode reproduces that state;
                    # ``publish`` leaves the two firmware-owned counters untouched.
                    selected = range(3)
                else:
                    selected = (g17p.CHANNEL_STATE_PRODUCER,)
                for index in selected:
                    if states[index]:
                        p.write32(states[index], target)
                        p.dc_civac(states[index], 4)
                secondary_state = {
                    "mode": secondary_mode,
                    "before": list(before),
                    "target": target,
                    "counters": secondary_counters(),
                    "read": secondary_counters,
                }
                print("  secondary runtime 5 x 0x22 (%s): %s -> %s"
                      % (secondary_mode, list(before),
                         list(secondary_state["counters"])))

            table_pa = arena.physical(CONTROL_OPERAND_TABLE_VA)
            if table_pa is None:
                raise RuntimeError("the live control operand table is not mapped")
            if os.getenv("G17P_FINAL_26_6_RUNTIME_PAIR") == "1":
                # Final 26.6 keeps the opening class-1 registration active and
                # advances it with sequence ticks.  The beta-era second class-1
                # registration crashes this firmware before pair-one work is
                # visible.
                control = announce_runtime_tick(
                    0, "final-26.6 runtime pair 0x2e")
                if not control["consumed"]:
                    raise RuntimeError(
                        "firmware did not consume the final-26.6 runtime tick: %r" %
                        control)
                runtime_control_sequence[0] = 1
                return {"0x2e": control, "final_26_6": True}
            if os.getenv("G17P_RUNTIME_EMPTY_OPERAND_TABLE") == "1":
                iface.writemem(table_pa, bytes(PAGE))
                print(
                    "  runtime operand table cleared to native pre-0x20 state",
                    flush=True,
                )
            else:
                for index in range(CONTROL_OPERAND_ENTRIES,
                                   CONTROL_OPERAND_ENTRIES_RUNTIME):
                    value = ((CONTROL_OPERAND_BUFFER_BASE
                              + index * CONTROL_OPERAND_BUFFER_STRIDE)
                             | CONTROL_OPERAND_SLOT_FLAG)
                    iface.writemem(
                        table_pa + index * CONTROL_OPERAND_ENTRY_STRIDE,
                        struct.pack("<Q", value),
                    )
            p.dc_civac(table_pa, PAGE)

            first_control = announce_runtime_tick(0, "runtime pair 0x2e")
            second_control = announce_control_entry(
                instances[0], ascs[0], build_control_20_entry_runtime(),
                "runtime pair 0x20 (slot 22, count 0x38)")
            if not second_control["consumed"]:
                raise RuntimeError(
                    "firmware did not consume the runtime pair registration: %r %r" %
                    (first_control, second_control))
            result = {"0x2e": first_control, "0x20": second_control}
            if secondary_state is not None:
                for _ in range(16):
                    with contextlib.suppress(Exception):
                        if ascs[1].has_messages():
                            ascs[1].work()
                    counters = secondary_state["read"]()
                    if counters[0] >= secondary_state["target"]:
                        break
                    time.sleep(0.001)
                result["secondary_0x22"] = {
                    "mode": secondary_state["mode"],
                    "before": secondary_state["before"],
                    "after": list(counters),
                }
                print("  secondary runtime counters after primary registration: %s"
                      % list(counters))
            if os.getenv("G17P_RUNTIME_PAIR_HOST_DELTA") == "1":
                # The later snapshot was trapped at the work doorbell, after
                # these runtime controls completed. Applying its delta before
                # the controls replays their counters and crashes opcode 0x20.
                apply_runtime_host_delta()
            runtime_control_sequence[0] = 1
            return result

        def register_compute_binding(with_predecessor=False,
                                     class2_support=None,
                                     sequence_base=None):
            """Convert the active pair record into its native CL_0 form."""
            table_pa = arena.physical(COMPUTE_BINDING_OPERAND_TABLE_VA)
            if table_pa is None:
                raise RuntimeError("compute binding operand table is not mapped")
            iface.writemem(table_pa, bytes(PAGE))
            p.dc_civac(table_pa, PAGE)
            u.inst("dsb sy")
            print("  compute binding operand table starts blank", flush=True)

            controls = []
            sequence = runtime_control_sequence[0]
            if sequence_base is not None:
                sequence = int(sequence_base)
                print(
                    "  compute binding sequence base set to %#x" % sequence,
                    flush=True,
                )
            if with_predecessor:
                sequence += 1
                predecessor = announce_control_entry(
                    instances[0], ascs[0],
                    build_control_20_entry_compute_binding(
                        sequence,
                        slot=COMPUTE_BINDING_PREDECESSOR_SLOT,
                        count=0x8),
                    "compute CL_0 predecessor 0x20 (slot 21, count 0x8)")
                if not predecessor["consumed"]:
                    raise RuntimeError(
                        "firmware did not consume compute CL_0 predecessor: %r" %
                        predecessor)
                predecessor_tick = announce_runtime_tick(
                    sequence, "compute CL_0 predecessor 0x2e")
                controls.append({
                    "sequence": sequence,
                    "0x20": predecessor,
                    "0x2e": predecessor_tick,
                })

            if class2_support is not None:
                sequence += 1
                context_word = int(class2_support.get("context_word", 1))
                support = announce_control_entry(
                    instances[0], ascs[0],
                    build_control_20_entry_class2(
                        class2_support["first_object"],
                        class2_support["operand_table"],
                        class2_support.get("slot_offset", 0x5c0),
                        sequence,
                        context_word=context_word,
                        count=class2_support.get("count", 0x18)),
                    "compute CL_0 class-2 support 0x20")
                if not support["consumed"]:
                    raise RuntimeError(
                        "firmware did not consume compute CL_0 class-2 support: %r" %
                        support)
                context_tick_body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                struct.pack_into("<II", context_tick_body, 0, 0x2e, sequence)
                struct.pack_into("<I", context_tick_body, 0x0c, context_word)
                context_tick = announce_control_entry(
                    instances[0], ascs[0], bytes(context_tick_body),
                    "compute CL_0 class-2 support 0x2e")
                if context_tick["crashed"] is not None:
                    raise RuntimeError(
                        "firmware crashed on compute CL_0 class-2 tick: %r" %
                        context_tick)
                controls.append({
                    "sequence": sequence,
                    "0x20": support,
                    "0x2e": context_tick,
                })
                sequence += 1
                trailing_tick_body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                struct.pack_into(
                    "<II", trailing_tick_body, 0, 0x2e, sequence)
                trailing_tick = announce_control_entry(
                    instances[0], ascs[0], bytes(trailing_tick_body),
                    "compute CL_0 class-2 trailing 0x2e")
                if trailing_tick["crashed"] is not None:
                    raise RuntimeError(
                        "firmware crashed on compute CL_0 trailing tick: %r" %
                        trailing_tick)
                controls.append({
                    "sequence": sequence,
                    "0x2e": trailing_tick,
                })
                sequence += 1
                registration = announce_control_entry(
                    instances[0], ascs[0],
                    build_control_20_entry_compute_binding(sequence),
                    "compute CL_0 binding 0x20 (slot 22, count 0x38)")
                if registration["crashed"] is not None:
                    raise RuntimeError(
                        "firmware crashed on compute CL_0 binding: %r" %
                        registration)
                binding_tick_body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                struct.pack_into("<II", binding_tick_body, 0, 0x2e, sequence)
                binding_tick = announce_control_entry(
                    instances[0], ascs[0], bytes(binding_tick_body),
                    "compute CL_0 binding 0x2e")
                if binding_tick["crashed"] is not None:
                    raise RuntimeError(
                        "firmware crashed on compute CL_0 binding tick: %r" %
                        binding_tick)
                sequence += 1
                final_tick = announce_runtime_tick(
                    sequence, "compute CL_0 final trailing 0x2e",
                    require_consumed=False)
                tick = {
                    "binding": binding_tick,
                    "trailing_sequence": sequence,
                    "trailing": final_tick,
                }
            else:
                sequence += 1
                registration = announce_control_entry(
                    instances[0], ascs[0],
                    build_control_20_entry_compute_binding(sequence),
                    "compute CL_0 binding 0x20 (slot 22, count 0x38)")
                if registration["crashed"] is not None:
                    raise RuntimeError(
                        "firmware crashed on compute CL_0 binding: %r" %
                        registration)
                tick = announce_runtime_tick(
                    sequence, "compute CL_0 binding 0x2e")
            runtime_control_sequence[0] = sequence
            return {
                "sequence": sequence,
                "predecessors": controls,
                "0x20": registration,
                "0x2e": tick,
            }

        def register_compute_control(
                control_class, first_object, operand_table,
                slot_offset=0x5c0, context_word=0, count=0x18,
                require_consumed=True, after_control=None, defer_tick=False):
            """Register one generated compact class-1/2 support object."""
            current = runtime_control_sequence[0]
            sequence = current + 1
            body = build_control_20_entry_object(
                control_class, first_object, operand_table, slot_offset,
                sequence, context_word=context_word, count=count)
            first_control = announce_control_entry(
                instances[0], ascs[0], body,
                "compute class-%d registration 0x20" % int(control_class))
            if first_control["crashed"] is not None:
                raise RuntimeError(
                    "firmware crashed on compute class-%d 0x20: %r" %
                    (int(control_class), first_control))
            if require_consumed and not first_control["consumed"]:
                raise RuntimeError(
                    "firmware did not consume compute class-%d 0x20: %r" %
                    (int(control_class), first_control))
            if after_control is not None:
                after_control(first_control)
            if defer_tick:
                runtime_control_sequence[0] = sequence
                return {
                    "sequence": sequence,
                    "class": int(control_class),
                    "0x20": first_control,
                    "0x2e": None,
                }
            tick = bytearray(g17p.CONTROL_MESSAGE_SIZE)
            struct.pack_into("<II", tick, 0, 0x2e, sequence)
            struct.pack_into("<I", tick, 0x0c, int(context_word))
            second_control = announce_control_entry(
                instances[0], ascs[0], bytes(tick),
                "compute class-%d registration 0x2e" % int(control_class))
            # Native streams put the next 0x20 directly behind this tick and
            # also contain consecutive ticks.  Firmware may leave 0x2e at the
            # producer until a later announcement, so only a crash is fatal.
            if second_control["crashed"] is not None:
                raise RuntimeError(
                    "firmware crashed on compute class-%d 0x2e: %r %r" %
                    (int(control_class), first_control, second_control))
            runtime_control_sequence[0] = sequence
            return {
                "sequence": sequence,
                "class": int(control_class),
                "0x20": first_control,
                "0x2e": second_control,
            }

        def register_compute_class2(
                first_object, operand_table, slot_offset=0x5c0,
                context_word=1, count=0x18, require_consumed=True,
                after_control=None, defer_tick=False):
            """Register one generated compute support object with class 2."""
            return register_compute_control(
                2, first_object, operand_table,
                slot_offset=slot_offset, context_word=context_word,
                count=count, require_consumed=require_consumed,
                after_control=after_control, defer_tick=defer_tick)

        def register_compute_class2_batch(records):
            """Publish complete class-2 0x20/0x2e pairs as one ring batch."""
            channel = g17p.CHANNEL_TABLE_WORK_COUNT
            instance = instances[0]
            asc = ascs[0]
            states = instance["channel_state_pas"][channel]

            def counters():
                values = []
                for pa in states[:3]:
                    p.dc_civac(pa, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(pa, 4)))[0])
                return tuple(values)

            before = counters()
            producer = before[g17p.CHANNEL_STATE_PRODUCER]
            bodies = []
            sequence = runtime_control_sequence[0]
            descriptions = []
            for record in records:
                sequence += 1
                context_word = int(record.get("context_word", 1))
                bodies.append(build_control_20_entry_class2(
                    record["first_object"], record["operand_table"],
                    record.get("slot_offset", 0x5c0), sequence,
                    context_word=context_word,
                    count=record.get("count", 0x18)))
                tick = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                struct.pack_into("<II", tick, 0, 0x2e, sequence)
                struct.pack_into("<I", tick, 0x0c, context_word)
                bodies.append(bytes(tick))
                descriptions.append({
                    "sequence": sequence,
                    "first_object": int(record["first_object"]),
                    "count": int(record.get("count", 0x18)),
                })

            for index, body in enumerate(bodies):
                slot = producer + index
                address = (instance["control_ring_pa"]
                           + slot * g17p.CONTROL_MESSAGE_SIZE)
                iface.writemem(address, body)
                p.dc_civac(address, len(body))
            target = producer + len(bodies)
            p.write32(states[g17p.CHANNEL_STATE_PRODUCER], target)
            p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 8)

            crashed = None
            for _ in bodies:
                try:
                    asc.db.send(DoorbellMsg(
                        TYPE=g17p.MSG_CONTROL_DONE,
                        CHANNEL=CONTROL_ANNOUNCE_PAYLOAD))
                    if asc.has_messages():
                        asc.work()
                except Exception as exc:
                    crashed = str(exc)
                    break
            after = counters()
            deadline = time.time() + 0.1
            while (crashed is None
                   and after[g17p.CHANNEL_STATE_CONSUMER] < target
                   and time.time() < deadline):
                try:
                    if asc.has_messages():
                        asc.work()
                except Exception as exc:
                    crashed = str(exc)
                    break
                time.sleep(0.001)
                after = counters()
            consumed = after[g17p.CHANNEL_STATE_CONSUMER] >= target
            print(
                "  compute class-2 batch slots %d..%d: %s -> %s  %s%s" %
                (producer, target - 1, list(before), list(after),
                 "consumed" if consumed else "not consumed",
                 "" if crashed is None else "  (crash: %s)" % crashed),
                flush=True,
            )
            runtime_control_sequence[0] = sequence
            return {
                "before": list(before), "after": list(after),
                "consumed": consumed, "crashed": crashed,
                "records": descriptions,
            }

        def advance_runtime_ticks(last_sequence, require_consumed=True):
            """Publish every ordinary primary tick through ``last_sequence``."""
            current = runtime_control_sequence[0]
            target = int(last_sequence)
            if target < current:
                raise ValueError(
                    "runtime tick target %#x precedes current sequence %#x" %
                    (target, current))
            results = []
            sequence = current + 1
            restart = os.getenv("G17P_CONTROL_RING_RESTART_SEQUENCE")
            restart = int(restart, 0) if restart is not None else None
            restarted = False
            while sequence <= target:
                result = announce_runtime_tick(
                    sequence, "runtime prefix 0x2e sequence %#x" % sequence,
                    require_consumed=bool(require_consumed))
                results.append(result)
                if (restart is not None and not restarted
                        and result["after"] == [255, 255, 255]):
                    sequence = restart
                    restarted = True
                else:
                    sequence += 1
            runtime_control_sequence[0] = target
            return {
                "first": current + 1,
                "last": target,
                "count": len(results),
                "restart": restart if restarted else None,
                "final": results[-1] if results else None,
            }

        def set_runtime_control_sequence(sequence):
            """Adopt the sequence represented by a prebuilt control history."""
            value = int(sequence)
            if value < 0:
                raise ValueError("runtime control sequence must be nonnegative")
            runtime_control_sequence[0] = value
            print(
                "  adopted prebuilt runtime control sequence %#x" % value,
                flush=True,
            )
            return value

        def announce_runtime_1b_grid(label="runtime 0x1b grid"):
            """Publish the six native pair-registration records in order."""
            grid = []
            for group in range(3):
                for lane in range(1, 3):
                    body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                    struct.pack_into("<III", body, 0, 0x1b, group, lane)
                    entry = announce_control_entry(
                        instances[0], ascs[0], bytes(body),
                        "%s (%d,%d)" % (label, group, lane))
                    if not entry["consumed"]:
                        raise RuntimeError(
                            "firmware did not consume runtime 0x1b (%d,%d): %r" %
                            (group, lane, entry))
                    grid.append(entry)
            return grid

        def announce_runtime_submission(ordinal):
            """Publish the sequenced primary 0x2e before each later work item.

            The pair-registration 0x2e carries zero. Subsequent native entries
            count from one, while ``ordinal`` counts the initial work group too,
            so the control-entry counter is ``ordinal - 1``.
            """
            if ordinal < 2:
                raise ValueError(
                    "runtime submission announcements start at ordinal 2")
            if (os.getenv("G17P_RUNTIME_NATIVE_SHARED_PRESTATE") == "1"
                    and ordinal >= 3):
                values = (0x1a0, 0x1ea0, 0, 0x1d00)
                for offset, value in zip(range(0x20, 0x30, 4), values):
                    address = SHARED_CONTROL_ADDRESS + offset
                    pa = leaf_output(uat, NATIVE_FIRMWARE_SLOT, address)
                    if pa is None:
                        raise RuntimeError(
                            "shared-control prestate address %#x is unmapped" % address)
                    pa += address & (PAGE - 1)
                    p.write32(pa, value)
                    p.dc_civac(pa, 4)
                u.inst("dsb sy")
                print(
                    "  native shared-control prestate +0x20..+0x2c = "
                    "0x1a0,0x1ea0,0,0x1d00",
                    flush=True,
                )
            result = announce_runtime_tick(
                ordinal - 1, "runtime submission %d 0x2e" % ordinal,
                update_sequence=True)
            if os.getenv("G17P_RUNTIME_1B_GRID") == "1" and ordinal >= 3:
                result["0x1b_grid"] = announce_runtime_1b_grid(
                    "runtime submission %d 0x1b" % ordinal)
            return result

        def capture_crash_postmortem(tag="post_submission_refusal"):
            """Force both live ASCs to emit crash buffers, then save mailbox histories."""
            global CRASH_CAPTURE_TAG

            CRASH_CAPTURE_TAG = "".join(
                character if character.isalnum() or character in "-_" else "_"
                for character in str(tag)
            )
            pending = set(range(len(ascs)))
            result = {}
            print("Provoking clean-room crash postmortem on both graphics ASCs (%s)"
                  % CRASH_CAPTURE_TAG)
            for index, instance in enumerate(ascs):
                try:
                    # Use RTKit's dedicated software-crash request. An invalid
                    # scheduler message can remain unhandled precisely when the
                    # scheduler is the task under investigation.
                    instance.crash.crash_soft()
                except Exception as exc:
                    result[instances[index]["name"]] = "send failed: %s" % exc
                    pending.discard(index)

            deadline = time.monotonic() + 3.0
            while pending and time.monotonic() < deadline:
                for index in tuple(pending):
                    instance = ascs[index]
                    try:
                        if instance.has_messages():
                            # One record per pass keeps a continuously asserted event
                            # endpoint from starving the crash notification.
                            instance.work()
                    except Exception as exc:
                        result[instances[index]["name"]] = str(exc)
                        pending.discard(index)
                time.sleep(0.001)
            for index in pending:
                result[instances[index]["name"]] = "no crash report within 3 seconds"
            print("Crash postmortem result: %r" % result)
            return result

        return {
            "attach": attach_state,
            "artifact": str(out / "boot.json"),
            "ascs": ascs,
            # Native first-partial topology retains this populated source tree
            # off the two hardware slots, whose upper roots are empty.
            "firmware_high_root": uat.ttbr1_base,
            "doorbell_message": DoorbellMsg,
            "control_message": GpuMsg,
            "announce_control_body": lambda body, label: announce_control_entry(
                instances[0], ascs[0], bytes(body), str(label)
            ),
            "announce_control_bodies": lambda bodies, label: announce_control_entries(
                instances[0], ascs[0], bodies, str(label)
            ),
            "announce_secondary_control_bodies": (
                lambda bodies, label: announce_control_entries(
                    instances[1], ascs[1], bodies, str(label)
                )
            ),
            "read_control_counters": lambda: {
                entry["name"]: list(control_counters(entry))
                for entry in instances
            },
            "drain_report_channels": lambda: drain_report_channels(
                arena, instances
            ),
            "announce_runtime_tick": announce_runtime_tick,
            "publish_runtime_tick": publish_runtime_tick,
            "stage_runtime_tick": stage_runtime_tick,
            "stage_secondary_runtime_22": stage_secondary_runtime_22,
            "register_runtime_pair": register_runtime_pair,
            "register_compute_binding": register_compute_binding,
            "register_compute_control": register_compute_control,
            "register_compute_class2": register_compute_class2,
            "register_compute_class2_batch": register_compute_class2_batch,
            "advance_runtime_ticks": advance_runtime_ticks,
            "set_runtime_control_sequence": set_runtime_control_sequence,
            "announce_runtime_1b_grid": announce_runtime_1b_grid,
            "announce_runtime_submission": announce_runtime_submission,
            "capture_crash_postmortem": capture_crash_postmortem,
            "capture_write_audit": CAPTURE_WRITE_AUDIT,
            "capture_read_audit": CAPTURE_READ_AUDIT,
            "strict_zero_capture": bool(args.require_zero_capture_pages),
            "render_execution_pages": render_execution_pages,
        }
    return 0 if acked else 1


if __name__ == "__main__":
    sys.exit(main())
