#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Start T8140/G17P firmware from scratch, with no captured state.

    M1N1DEVICE=/dev/m1n1-neo PYTHONPATH=proxyclient \
        .venv/bin/python3 proxyclient/experiments/agx_g17p_coldboot.py

Runs bare metal against a chainloaded m1n1: no macOS guest, no hypervisor and no
snapshot restore. Everything the firmware is handed is built here, in memory this
script allocates and maps itself:

  * an address space of our own, using m1n1's translation-table code, bound to a
    context the firmware is not already using
  * the descriptor root, main configuration object, hardware-data object, data
    region and status blocks, from the builder in m1n1/agx/g17p_initdata.py
  * channel state blocks and rings

The replay path answered whether a constructed descriptor is well formed. This
answers the different question of whether firmware will start on an address space
the host owns, which is what a driver has to do. Replaying a capture remains the
right tool when the question is what macOS does; it is the wrong tool for probing
hardware we can drive ourselves.

The address layout follows the accelerator's own device tree properties rather than
anything captured: the region above the coprocessor's private range is where the
firmware's objects are expected to live.
"""

import argparse
import contextlib
import datetime
import json
import pathlib
import struct
import sys
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.setup import p, u, iface           # noqa: E402
from m1n1.constructutils import Ver          # noqa: E402

# The translation-table layout depends on the accelerator generation, and the module
# that implements it picks a layout at import time. The generation has to be
# published from the device tree before that import happens. Skipping this leaves
# the older layout in force, which splits the address space one bit lower than this
# part does: the tables then look self-consistent to the host and translate nothing
# for the coprocessor.
Ver.set_version(u)
if Ver._version.get("V") is None:
    # The host operating system version is only knowable when one is running, and
    # nothing here is. It selects between layouts of structures this script does not
    # build, so the newest known value is a safe stand-in and keeps those definitions
    # importable.
    Ver.set_version_key("V", Ver.MATRIX["V"][-1])

from m1n1.fw.asc import StandardASC          # noqa: E402
from m1n1.hw.asc import R_MBOX_CTRL          # noqa: E402
from m1n1.fw.asc.base import (ASCBaseEndpoint, ASCMessage1, ASCTimeout,  # noqa: E402
                              msg_handler)
from m1n1.fw.asc.crash import ASCCrashLogEndpoint, CrashLogParser  # noqa: E402
from m1n1.fw.asc.mgmt import (ASCManagementEndpoint, Mgmt_EPMap,
                              Mgmt_EPMap_Ack)  # noqa: E402
from m1n1.malloc import Heap                 # noqa: E402
from m1n1.utils import Register64            # noqa: E402
from m1n1.hw.uat import UAT, MemoryAttr      # noqa: E402
from m1n1.agx import g17p                    # noqa: E402
from m1n1.agx import g17p_initdata as build  # noqa: E402
from m1n1.agx.g17p_phase_state import save_phase_state  # noqa: E402

PAGE = 0x4000
ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
DEFAULT_NATIVE_SNAPSHOT = ARTIFACTS / (
    "initdata_pre_submit_all_uat_roots_v2_20260724_150935"
)
DEFAULT_RENDER_SNAPSHOT = ARTIFACTS / "pre_work_0x83_v2_20260724_193713"

# The render context a submission draws in. The replay path reaches it by restoring a
# captured world; this builds it, so it has to name every page and say where the page's
# content comes from.
RENDER_CONTEXT_BASE = 0x1000000000

# The parameters of the render whose register programs this project reproduces byte for
# byte offline, in agx_g17p_validate_render_recipe.py. Everything here is either a
# dimension or the address of an object listed in RENDER_PAGES below.
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

# Every render page the two register programs name or the tiler stream binds, with the
# captured leaf's execute permission and where the page's content comes from:
#
#   generate  built here, and checked against the capture before it is used
#   zero      firmware and the accelerator fill it; a fresh page is correct
#   seed      content this project cannot generate, taken from a capture
#
# The measured totals: fourteen pages, eight with content, 1,610 non-zero bytes, of which
# 1,463 are the compiled load and store pipelines. UXN comes from the captured PTEs, where
# four of the fourteen leaves are executable.
RENDER_PAGES = (
    (0x1000000000,  0, "seed",     "bind0"),
    (0x1000018000,  0, "generate", "tiler_stream"),
    (0x1000048000,  0, "seed",     "index_buffer"),
    (0x1000058000,  1, "seed",     "bind1_2_3_4_6_7"),
    (0x1000068000,  1, "seed",     "bind5_and_deflake"),
    (0x1000078000,  1, "zero",     "ta_status"),
    (0x10001990000, 1, "seed",     "load_store_pipelines"),
    (0x100019a0000, 1, "generate", "scissor_array"),
    (0x10001a8000,  1, "zero",     "fragment_status"),
    (0x10001aa8000, 1, "seed",     "aux_fb"),
    (0x10001af8000, 0, "zero",     "depth_bias_array"),
    (0x10001b0000,  1, "zero",     "tilemap"),
    (0x10001b4000,  1, "zero",     "heapmeta"),
    (0x1000240000,  1, "zero",     "tile_parameter_cache"),
)

# Nine further values in the two register programs would resolve to mapped render pages if
# they are addresses rather than configuration words. Most are recognisably geometry or
# flags, and mappedness is not evidence in this dense context, so this does not claim they
# are addresses. All nine are zero in the capture, so a fresh page is correct either way,
# and mapping them removes a class of translation fault from the first cold-boot render.
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

# The captured render leaves all carry these, and the four bits that matter are not the
# firmware context's: access permission 2 rather than 1, non-global, and not outer
# shareable. Mapping them the firmware context's way puts the pages behind permissions the
# accelerator does not have.
RENDER_PAGE_FLAGS = {
    "AttrIndex": MemoryAttr.Shared,
    "AP": 2,
    "AF": 1,
    "nG": 1,
    "SH": 0,
    "OS": 1,
}

# The low alias region, `0x70...`, is part of the render context and its leaves carry the render
# context's attributes rather than the firmware context's: access permission 2 and non-global, not
# the arena's 1 and global. Everything this path places there, the two context/queue low aliases,
# the operand table and the operand buffers, had the firmware context's.
LOW_ALIAS_FLAGS = dict(RENDER_PAGE_FLAGS, UXN=1)

# Which of the objects this path builds a working host maps fully cached rather than inner
# non-cacheable. Read from the capture's own leaves: the queue records, the item rings, the shared
# control object and the channel control array are `AttrIndex 0`, while the queue pointer block, the
# context/queue firmware aliases and the shared control object's inner target are `AttrIndex 2`.
NORMAL_OBJECT_FLAGS = {"AttrIndex": MemoryAttr.Normal, "AP": 1}

# Which UAT root the render context's low addresses live behind, and which the capture
# recorded them under.
RENDER_SNAPSHOT_ROOT = 7

# The context and queue state a first-work optional item names, which the replay path
# inherits from a capture and a cold boot has to build. Four objects and about 110 bytes of
# content between them:
#
#   one page per kind, carrying that kind's work descriptor and queue addresses, seen at a
#     low alias and a firmware alias resolving to one physical page
#   a shared control object, naming the operand table and one further word
#   a channel control array of 0x40-byte records
#
# Fields whose roles are not separated carry the captured value, which is this record's
# convention for such fields; the two addresses are substituted with this path's own.
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
# Where each of these objects goes. The capture's own addresses, deliberately: the tails and the
# optional items name them, several of them are in the low alias region rather than the firmware
# region, and an earlier run that allocated replacements from one cursor moved two low-region
# objects into the firmware region. Whether they relocate is a separate question from whether a
# cold boot can build their content, and this fixes the addresses so only the content varies.
CONTEXT_QUEUE_ADDRESSES = {
    "tiling": {"low": 0x7000438000, "high": 0xfffffc20001d8000},
    "fragment": {"low": 0x7000460000, "high": 0xfffffc2000200000},
}
SHARED_CONTROL_ADDRESS = 0xfffffc20c0830000
SHARED_CONTROL_INNER_ADDRESS = 0xfffffc2001608000

# The shared control object is one object, and it is named twice: by the device-control `0x20`
# entry at that entry's `+0x14`, and by every first-work optional item at its `+0x36`. This path
# built it twice, once for each, at two different addresses, so firmware registered one copy
# through the opening sequence and the work referenced the other. The record says the
# parameter-buffer binding must happen through the opening sequence, which is the only messaging
# that precedes it, and a registration naming an object the work does not use cannot bind it.
#
# Its two phase-dependent fields: the cursor at `+0x48` reads `0x88` before the first `0x20` and
# `0xb0` after, and byte zero of the object at `+0x4c` reads 1 before and 2 after. A host builds
# the before values and firmware advances them.
SHARED_CONTROL_COUNT_BEFORE = 0x88
SHARED_CONTROL_COUNT_AFTER = 0xb0
SHARED_CONTROL_INNER_BEFORE = 1
SHARED_CONTROL_INNER_AFTER = 2
CHANNEL_CONTROL_ADDRESS = 0xfffffc20c07b8000

# Where the backend heap goes, and it is not an arbitrary choice. The firmware context divides
# cleanly in two: every one of the 494 pages at `0xfffffc20c0......` is `AttrIndex 0`, fully cached,
# and every one of the 132 pages below it is `AttrIndex 2`, inner non-cacheable. And every
# submission object a working host builds lives in the high one: the queue records at
# `0xc0000000`, the item rings at `0xc0008000`, the two descriptors at `0xc0018000` and
# `0xc00b0000`, the optional items at `0xc0600000`, the event items at `0xc05e8000`, the pools at
# `0xc0868000`, the main object, the work rings, and the shared and channel control objects. The
# low region holds the roots, the data region, the channel state block, the private cluster and the
# queue pointer blocks.
#
# This heap sat at `0xfffffc2000400000`, in the low region, so every submission object this path
# builds was in the region a host uses for a different class of object. Moved above the capture's
# own span, which ends at `0xfffffc20c0868000`, so it is in the right region and collides with
# nothing the firmware extent maps.
BACKEND_HEAP_VA_BASE = 0xfffffc20c0900000

# The queue pointer blocks are the exception to that rule, and moving the whole heap into the upper
# region moved them the wrong way. A working host keeps its two at `0xfffffc2000010000` and
# `0xfffffc2000012870`, `0x2870` apart inside **one** low-region page, `AttrIndex 2`, alongside the
# roots and the channel state rather than with the submission objects. The same `0x2870` stride
# separates its two item rings, so it is the per-queue allocation unit.
#
# This base is in the low region and clear of every page the capture maps.
QUEUE_POINTER_BLOCK_VA = 0xfffffc2000300000
QUEUE_POINTER_BLOCK_STRIDE = 0x2870

# The job list is a low-region object too, and both queues of a pair share one: the capture has
# both naming `0xfffffc2000000018`. This path had it in the upper-region heap.
QUEUE_JOB_LIST_VA = QUEUE_POINTER_BLOCK_VA + 0x3000

# The low payload of the `0x84` message that announces a device-control entry. A host's is
# constant and names nothing, and it is not a channel number: the replay path sends this value.
CONTROL_ANNOUNCE_PAYLOAD = 0x11

# Which of the accelerator's device-tree carveouts a host can usefully seed, established by
# trying each on hardware. The two shared regions are the ones this path leaves zero and that
# firmware maps for itself; every other carveout is either this path's own, the coprocessors'
# own, or protected.
SEEDABLE_FIXED_REGIONS = ("gfx-shared-region", "gfx-shared-l2-region")

# How a working host arranges the translation root table: twelve slots, of which three are in use.
# The slot is the table position and the context id is the ASID field of the slot's root pointers,
# so the two are independent, and a work item names the context id rather than the slot.
# The queue record's `+0x48`. The field is named uuid and described as counting up per queue, but
# both queues of the captured pair hold the same value, so it is not a per-queue counter there.
# Using it makes the built record byte-exact against the capture, which is the last field of the
# submission path that was not.
QUEUE_UUID_VALUE = 0xa6

# The counters the firmware-produced channels carry in the world that renders. Channels 13 and 14
# are firmware's to produce on, and a fresh firmware in that world inherits state showing prior
# activity where this path starts every counter at zero.
REPORT_CHANNEL_COUNTERS = {13: (1, 13, 0), 14: (8, 5, 0)}

# The second instance's opening sequence, read from a working world's own control ring: three bare
# `0x2a` entries and then thirteen bare `0x22`, sixteen in all, which is exactly what its
# device-control counters read there. This path has always staged a single `0x2a`.
#
# `0x22` is not in the vocabulary this record had catalogued; that list, `0x16`, `0x20` and `0x2e`,
# was the primary's. The second instance is now known to be a precondition for the primary
# servicing its work channels at all, so what it is asked to do is not incidental.
SECONDARY_CONTROL_SEQUENCE = ((0x2a, 3), (0x22, 13))

NATIVE_FIRMWARE_SLOT = 1
NATIVE_FIRMWARE_CONTEXT = 64
NATIVE_RENDER_SLOT = 7
NATIVE_RENDER_CONTEXT = 1

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
# An unaligned pointer, with a count beside it, to an object holding a single word.
SHARED_CONTROL_COUNT_AT = 0x48
SHARED_CONTROL_COUNT = 0xb0
SHARED_CONTROL_INNER_AT = 0x4c
SHARED_CONTROL_INNER_WORD = 0x0000000000000002

CHANNEL_CONTROL_STRIDE = 0x40
CHANNEL_CONTROL_RECORDS = 2
CHANNEL_CONTROL_ITEM_RECORD = 1
CHANNEL_CONTROL_WORDS = (
    (0x00, 0x000001000000ffff),
    (0x20, 0x0002000000000000),
    (0x30, 0x00000000ff000000),
)

# The work descriptor has two views. The queue parser reads a compact body ending after the
# register array, which is what the builder produces; the context-global locator reads on past
# it, and on hardware a record with nothing there faulted. So the record has to be extended to
# its full size, and the bytes past the register array come from a capture: 64 non-zero bytes
# for tiling, 177 for fragment.
DESCRIPTOR_TAIL = {
    "tiling": {"captured": 0xfffffc20c0018000, "built": 0x3cc, "native": 0x9c0},
    "fragment": {"captured": 0xfffffc20c00b0000, "built": 0x4cc, "native": 0x2240},
}

# Every address those tails hold, at the offset it is held at. Several are unaligned, which is
# why they are listed rather than found by scanning. Each is rewritten to name this path's own
# object, keeping its offset within the page.
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
#   shared     the shared control object build_context_queue_state builds
#   status     a firmware-context alias of a render status page; the tail carries the second,
#              authoritative status locator, and leaving it captured kept the accelerator's
#              status writes on the captured pages in an earlier replay
#   seed       a page of this path's own carrying the captured content
#   fresh      a page of this path's own, zero, as the capture has it
DESCRIPTOR_TAIL_TARGETS = {
    0x1000240000: ("render", None),
    0x1000000000: ("render", None),
    0xfffffc20c0830000: ("shared", None),
    0xfffffc2001610000: ("status", "ta_status"),
    0xfffffc2001630000: ("status", "fragment_status"),
    # Each work descriptor is mapped a second time at a low address, and the pointers its tail
    # carries into these two pages are the descriptor referring to **itself** through that alias:
    # the tiling tail's `+0x760` holds its own low alias `+0x60`, and the fragment tail's `+0x7a0`,
    # `+0xec0`, `+0x15e0` and `+0x1d00` hold its own `+0xa0`, `+0x7c0`, `+0xee0` and `+0x1600`.
    # Treating them as unrelated pages and seeding copies, which is what this path did, points the
    # descriptor at something that is not itself.
    0x7000000000: ("self", "tiling"),
    0x7000098000: ("self", "fragment"),
    0xfffffc2000024000: ("seed", None),
    0xfffffc20001c8000: ("fresh", None),
    0xfffffc20c07c0000: ("fresh", None),
}

# Where each work descriptor's low alias goes. Clear of every page the capture maps.
DESCRIPTOR_LOW_ALIAS = {"tiling": 0x7000600000, "fragment": 0x7000700000}


class GpuMsg(Register64):
    TYPE = 63, 48


class InitMsg(GpuMsg):
    TYPE = 63, 48
    INITDATA = 43, 0


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
        # Worth printing rather than only counting. A world that renders raises three of these,
        # one at initialisation and one per work channel when the work runs; this path has only
        # ever raised the first. It is an immediate witness where the render scan is distal.
        self.events += 1
        print("  [fw] event %d: %#x" % (self.events, int(msg.value)))
        return True


class DoorbellMsg(GpuMsg):
    TYPE = 63, 48
    CHANNEL = 15, 0


class DoorbellEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GpuMsg
    SHORT = "db"


# Reading the crash report is off by default. It is turned on when a fault has to
# be located, because the report is firmware's own diagnostic state, registers and
# a mapping list, which is what every fault in this record was tracked down with.
READ_CRASH = False


class SafeCrashLogEndpoint(ASCCrashLogEndpoint):
    """Keep the normal crash-buffer handshake, reading the report only on request."""

    def handle_crashed(self, msg):
        callback = getattr(self.asc, "g17p_fatal_callback", None)
        if callback is not None:
            if READ_CRASH:
                size = 0x1000 * msg.SIZE
                try:
                    crashdata = self.asc.ioread(msg.DVA, size)
                    stamp = datetime.datetime.now().strftime(
                        "%Y%m%d_%H%M%S_%f")
                    ARTIFACTS.mkdir(parents=True, exist_ok=True)
                    artifact = ARTIFACTS / ("g17p_fatal_%s.bin" % stamp)
                    artifact.write_bytes(crashdata)
                    self.asc.g17p_fatal_report = str(artifact)
                    self.log("preserved fatal report at %s" % artifact)
                    CrashLogParser(crashdata, self.asc).dump()
                except Exception as exc:
                    # Preserve the fence terminal path even when the report is
                    # truncated or a new entry type defeats the parser.
                    self.asc.g17p_fatal_report_error = str(exc)
            else:
                self.log("firmware crash notification at dva %#x (%#x bytes); "
                         "crash payload intentionally not read" %
                         (msg.DVA, 0x1000 * msg.SIZE))
            callback(self, msg)
            return True
        if READ_CRASH:
            return super().handle_crashed(msg)
        self.log("firmware crash notification at dva %#x (%#x bytes); "
                 "crash payload intentionally not read" %
                 (msg.DVA, 0x1000 * msg.SIZE))
        raise RuntimeError("ASC firmware reported a crash")


class NativeCrashLogEndpoint(SafeCrashLogEndpoint):
    """Acknowledge a firmware-preallocated crash buffer as the native host does."""

    def handle_getbuf(self, msg):
        if not msg.DVA:
            return super().handle_getbuf(msg)

        self.iobuffer_dva = msg.DVA
        self.log("buf prealloc at dva %#x" % self.iobuffer_dva)
        self.send(msg)
        self.started = True
        return True


class NativeManagementEndpoint(ASCManagementEndpoint):
    """Reproduce the management-message ordering observed on the native host."""

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

        # The native host starts the crash endpoint before acknowledging the
        # first map which advertises it.
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


class ColdASC(StandardASC):
    ENDPOINTS = {
        0x01: SafeCrashLogEndpoint,
        0x20: FirmwareEndpoint,
        0x21: DoorbellEndpoint,
    }


class NativeColdASC(ColdASC):
    ENDPOINTS = {
        0x01: NativeCrashLogEndpoint,
        0x20: FirmwareEndpoint,
        0x21: DoorbellEndpoint,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_ep(0, NativeManagementEndpoint(self, 0))


class AbsentHandoff:
    """Stand-in for the translation-table handoff on parts that do not use it.

    The handoff is a mutual-exclusion structure for two agents editing the same
    translation tables, and its lock protocol only completes when the firmware
    publishes its half of a magic value. Nothing publishes it here, and nothing
    needs to: on bare metal this script is the only agent editing the tables, so
    the lock has no second party to exclude.
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


class Arena:
    """Host memory mapped into the firmware's address space at chosen addresses."""

    def __init__(self, uat, ctx, base_va):
        self.uat = uat
        self.ctx = ctx
        self.va = base_va
        self.entries = []

    def alloc(self, size, name, data=None):
        size = (size + PAGE - 1) & ~(PAGE - 1)
        pa = u.memalign(PAGE, size)
        iface.writemem(pa, data if data is not None else bytes(size))
        p.dc_civac(pa, size)
        va = self.va
        self.uat.iomap_at(self.ctx, va, pa, size,
                          AttrIndex=MemoryAttr.Shared, AP=1)
        self.va += size
        self.entries.append({"name": name, "va": va, "pa": pa, "size": size})
        print("  %-16s va %#018x  pa %#014x  %#x bytes" % (name, va, pa, size))
        return va, pa

    def alloc_at(self, va, size, name, data=None, flags=None):
        """Map one object at an exact, possibly subpage-aligned DVA."""
        page_va = va & ~(PAGE - 1)
        offset = va - page_va
        span = (offset + size + PAGE - 1) & ~(PAGE - 1)
        page_pa = u.memalign(PAGE, span)
        iface.writemem(page_pa, bytes(span))
        if data is not None:
            iface.writemem(page_pa + offset, data)
        p.dc_civac(page_pa, span)
        self.uat.iomap_at(self.ctx, page_va, page_pa, span,
                          **(flags or {"AttrIndex": MemoryAttr.Shared, "AP": 1}))
        pa = page_pa + offset
        self.entries.append({"name": name, "va": va, "pa": pa, "size": size})
        print("  %-16s va %#018x  pa %#014x  %#x bytes (exact DVA)"
              % (name, va, pa, size))
        return va, pa

    def write(self, pa, data):
        iface.writemem(pa, data)
        p.dc_civac(pa, len(data))


class BackendArena:
    """A bump allocator over the cold boot's arena, shaped the way the backend wants.

    The backend asks for small objects and returns only device addresses; the arena hands out
    whole pages and returns both halves. Carving pages up keeps the allocation count sane, and
    keeping the physical alias lets a write go straight to memory.
    """

    def __init__(self, arena):
        self.arena = arena
        self.pages = []
        self.cursor = 0
        self.base = 0
        self.base_pa = 0

    def alloc(self, size, name="object"):
        size = int(size)
        if size > PAGE:
            va, pa = self.arena.alloc(size, name)
            self.pages.append((va, pa, size))
            return va
        aligned = (self.cursor + 0x3f) & ~0x3f
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

    They are loaded by path rather than imported because the sibling modules reach each other
    through a package name, and the copy already imported as ``m1n1.agx`` carries the older
    generation's structures.
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
                 "g17p_backend"):
        spec = importlib.util.spec_from_file_location(
            "g17pbackend." + name, directory / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules["g17pbackend." + name] = module
        setattr(package, name, module)
        spec.loader.exec_module(module)
    return package


def build_render_context(arena, uat, context, snapshot, full_extent=False,
                         seed_all_render=False):
    """Map the render context a verified submission draws in, and say where each page came from.

    The register programs name render-context objects, and the tiler stream binds more. The
    replay path gets all of them by restoring a captured world; a cold boot has to place every
    one itself. Fourteen pages, of which six are zero in the capture and are therefore correct
    as fresh allocations, two are generated here and checked against the capture before use, and
    six carry content this project cannot generate. 1,463 of those content bytes are the
    compiled load and store pipelines, which is the documented gap: nothing here compiles
    shaders.
    """
    package = load_backend_modules()
    render = package.g17p_render
    encoder_module = package.g17p_encoder

    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    captured = {}
    for group in manifest["root_mappings"]:
        if int(group["root_index"]) != RENDER_SNAPSHOT_ROOT:
            continue
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            index = int(mapping["blob_index"])
            captured[int(mapping["va"])] = ram[index * PAGE:(index + 1) * PAGE]

    parameters = render.G17PRenderParameters(**RENDER_PARAMETERS)

    # The tiler stream is generated from parameters recovered from the captured one, and the
    # result has to be the captured bytes: a stream that merely happens to be in place is not
    # evidence that this path can build one.
    stream_page = RENDER_PARAMETERS["encoder"] & ~(PAGE - 1)
    stream_offset = RENDER_PARAMETERS["encoder"] & (PAGE - 1)
    captured_stream = captured[stream_page][
        stream_offset:stream_offset + encoder_module.ENCODER_SIZE]
    built_stream = encoder_module.build_encoder(
        encoder_module.parse_encoder(captured_stream, RENDER_CONTEXT_BASE))
    if built_stream != captured_stream:
        raise RuntimeError("generated tiler stream differs from the capture")

    # The scissor record is the render dimensions and a scale, so it is derived rather than
    # copied, and the same equality check applies.
    scissor_body = struct.pack(
        "<IIIf", RENDER_PARAMETERS["width"], RENDER_PARAMETERS["height"], 0, 1.0)
    scissor_page = RENDER_PARAMETERS["scissor_array"] & ~(PAGE - 1)
    scissor_offset = RENDER_PARAMETERS["scissor_array"] & (PAGE - 1)
    captured_scissor = captured[scissor_page][
        scissor_offset:scissor_offset + len(scissor_body)]
    if scissor_body != captured_scissor:
        raise RuntimeError("generated scissor record differs from the capture")

    print("Building the render context at base %#x" % RENDER_CONTEXT_BASE)
    extent = None
    records = []
    seeded_bytes = 0
    bodies = {}
    for page_va, uxn, source, name in (
            RENDER_PAGES
            + tuple((va, uxn, "zero", name) for va, uxn, name in RENDER_GUARD_PAGES)):
        if source == "zero":
            body = bytes(PAGE)
        elif source == "seed":
            body = captured[page_va]
            seeded_bytes += sum(byte != 0 for byte in body)
        else:
            body = bytearray(PAGE)
            if name == "tiler_stream":
                body[stream_offset:stream_offset + len(built_stream)] = built_stream
            elif name == "scissor_array":
                body[scissor_offset:scissor_offset + len(scissor_body)] = scissor_body
            else:
                raise RuntimeError("no generator for %s" % name)
            body = bytes(body)
            if body != captured[page_va]:
                raise RuntimeError(
                    "generated page %s differs from the capture" % name)
        if any(body):
            bodies[page_va] = body
        records.append({"name": name, "va": page_va, "source": source, "uxn": uxn,
                        "nonzero": sum(byte != 0 for byte in body)})

    if full_extent:
        # Every run the capture has, so the accelerator has the room it writes into. The named
        # pages fall inside those runs, so their content goes in as the runs are placed rather
        # than being mapped separately, which would double-map them.
        mapped, heads = map_full_render_extent(
            arena, uat, context, snapshot, bodies, seed_all=seed_all_render)
        extent = {"mapped": mapped, "heads": heads}
        for record in records:
            record["pa"] = mapped[record["va"]]
    else:
        for record in records:
            page_pa = u.memalign(PAGE, PAGE)
            iface.writemem(page_pa, bodies.get(record["va"], bytes(PAGE)))
            p.dc_civac(page_pa, PAGE)
            uat.iomap_at(context, record["va"], page_pa, PAGE,
                         UXN=record["uxn"], **RENDER_PAGE_FLAGS)
            arena.entries.append({"name": "render_" + record["name"],
                                  "va": record["va"], "pa": page_pa, "size": PAGE})
            record["pa"] = page_pa
        uat.flush_dirty()

    print("  %d pages: %d generated and checked, %d fresh, %d seeded (%d non-zero bytes)"
          % (len(records),
             sum(1 for r in records if r["source"] == "generate"),
             sum(1 for r in records if r["source"] == "zero"),
             sum(1 for r in records if r["source"] == "seed"), seeded_bytes))
    for record in records:
        print("    %-22s %#014x  %-8s %5d non-zero%s"
              % (record["name"], record["va"], record["source"],
                 record["nonzero"], "  executable" if not record["uxn"] else ""))
    return {"parameters": parameters, "pages": records, "extent": extent,
            "registers": {
                "tiling": render.build_tiling_registers(parameters),
                "fragment": render.build_fragment_registers(parameters),
            }}


def control_channel_tick(instance, asc, count, start=0, label="tick"):
    """Publish opcode-`0x2e` device-control entries, as a booted host does continuously.

    A mid-stream capture's ring holds `0x2e` entries after the three `0x16` and the `0x20`, with
    counters climbing, so a host publishes them.

    This docstring used to say firmware refuses every device-control entry published after the first
    work, "whether or not it is announced". **That is wrong and is withdrawn.** Measured directly on
    2026-07-31: an entry published on the running primary and followed by a `0x84` is consumed and
    executed, its counters tracking the producer and the shared control object's cursor advancing by
    the entry's own command count. Only an entry published without that `0x84` is left alone, and
    that is what every earlier measurement here did.

    So this function publishes what a host publishes, and a running firmware does take it, provided
    it is announced. Use ``announce_control_entry`` in the boot experiment for that; publishing
    without an announcement is not a test of whether firmware accepts the entry.

    The ring is at the main configuration object `+0x4c0` and the entry the builder models as a
    scalar field there is really the ring's first entry, so the opening leaves the producer at
    four and these go in at index four onwards.
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

    results = []
    for index in range(count):
        before = counters()
        producer = before[g17p.CHANNEL_STATE_PRODUCER]
        body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into("<II", body, 0, 0x2e, start + index)
        iface.writemem(ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, bytes(body))
        p.dc_civac(ring_pa + producer * g17p.CONTROL_MESSAGE_SIZE, len(body))
        p.write32(states[g17p.CHANNEL_STATE_PRODUCER], producer + 1)
        p.dc_civac(states[g17p.CHANNEL_STATE_PRODUCER], 8)
        crashed = None
        after = before
        deadline = time.time() + 0.05
        while time.time() < deadline:
            try:
                # The 0x84 announce carries a constant low payload rather than a channel
                # number. Sending zero there left every entry unconsumed.
                asc.db.send(DoorbellMsg(TYPE=g17p.MSG_CONTROL_DONE,
                                        CHANNEL=CONTROL_ANNOUNCE_PAYLOAD))
                asc.work_pending()
            except Exception as exc:
                crashed = str(exc)
                break
            after = counters()
            if after[g17p.CHANNEL_STATE_CONSUMER] > before[g17p.CHANNEL_STATE_CONSUMER]:
                break
            time.sleep(0.001)
        taken = after[g17p.CHANNEL_STATE_CONSUMER] > before[g17p.CHANNEL_STATE_CONSUMER]
        results.append({"counter": start + index, "slot": producer,
                        "before": list(before), "after": list(after),
                        "consumed": bool(taken), "crashed": crashed})
        print("  control %s %d at slot %d: %s -> %s  %s%s"
              % (label, start + index, producer, list(before), list(after),
                 "CONSUMED" if taken else "not consumed",
                 "" if crashed is None else "  (crash: %s)" % crashed))
        if crashed is not None:
            break
    return results


def build_context_queue_state(arena, uat, context, seed_from=None, phase="before"):
    """Build the four objects a first-work optional item names.

    The cold-boot path used to hand the optional items four fresh zero pages, and the scheduler
    faulted on a null dereference while examining the group at initialisation, identically with
    an empty and with a complete register program. These are the objects the replay path
    inherits instead. Each kind's page is mapped twice onto one physical page, because that is
    how the capture holds it: a low alias and a firmware alias of the same memory.

    The two addresses each page carries are written later, once the descriptor and the queue
    exist. Everything else is filled here.
    """
    def alloc_page(name):
        pa = u.memalign(PAGE, PAGE)
        iface.writemem(pa, bytes(PAGE))
        p.dc_civac(pa, PAGE)
        return pa

    captured = None
    if seed_from is not None:
        # Bisecting: the built content models the words that are non-zero in the capture, and a
        # word missed there is invisible. Seeding the whole page instead separates "this path
        # cannot build the content" from "the content is not what is missing".
        manifest = json.loads((seed_from / "manifest.json").read_text())
        ram = (seed_from / manifest["ram_file"]).read_bytes()
        blobs = {}
        for mapping in manifest["mappings"]:
            if mapping.get("blob_index") is not None:
                blobs.setdefault(int(mapping["va"]), int(mapping["blob_index"]))
        captured = {}
        for kind, addresses in CONTEXT_QUEUE_ADDRESSES.items():
            index = blobs[addresses["high"]]
            captured[kind] = ram[index * PAGE:(index + 1) * PAGE]

    print("Building the context and queue state the optional items name%s"
          % ("" if captured is None else ", seeded whole from the capture"))
    state = {"pages": {}, "records": []}
    for kind in ("tiling", "fragment"):
        pa = alloc_page("context_queue_%s" % kind)
        if captured is not None:
            body = bytearray(captured[kind])
        else:
            body = bytearray(PAGE)
            for offset, value in CONTEXT_QUEUE_WORDS[kind]:
                struct.pack_into("<Q", body, offset, value)
        iface.writemem(pa, bytes(body))
        p.dc_civac(pa, PAGE)

        high_va = CONTEXT_QUEUE_ADDRESSES[kind]["high"]
        low_va = CONTEXT_QUEUE_ADDRESSES[kind]["low"]
        for va in (high_va, low_va):
            # The low alias belongs to the render context and carries its attributes, access
            # permission 2 and non-global; the firmware alias keeps the firmware context's.
            flags = (LOW_ALIAS_FLAGS if va == low_va
                     else {"AttrIndex": MemoryAttr.Shared, "AP": 1})
            uat.iomap_at(context, va, pa, PAGE, **flags)
            arena.entries.append({"name": "context_queue_%s_%s"
                                          % (kind, "high" if va == high_va else "low"),
                                  "va": va, "pa": pa, "size": PAGE})
        state["pages"][kind] = {"pa": pa, "high": high_va, "low": low_va}
        print("  %-8s context/queue page at %#x and %#x, one page at pa %#x"
              % (kind, low_va, high_va, pa))

    inner_pa = alloc_page("shared_control_inner")
    inner_va = SHARED_CONTROL_INNER_ADDRESS
    # Before the first `0x20` this reads 1; firmware advances it to 2. The captured value is the
    # later one, so building it means building the earlier, unless the caller is presenting the
    # world as already past the opening, which is the state the only rendering world is in.
    iface.writemem(inner_pa, struct.pack(
        "<Q", SHARED_CONTROL_INNER_AFTER if phase == "after"
        else SHARED_CONTROL_INNER_BEFORE))
    p.dc_civac(inner_pa, PAGE)
    uat.iomap_at(context, inner_va, inner_pa, PAGE,
                 AttrIndex=MemoryAttr.Shared, AP=1)
    arena.entries.append({"name": "shared_control_inner", "va": inner_va,
                          "pa": inner_pa, "size": PAGE})

    shared_pa = alloc_page("shared_control")
    shared_va = SHARED_CONTROL_ADDRESS
    body = bytearray(PAGE)
    for offset, value in SHARED_CONTROL_WORDS:
        struct.pack_into("<Q", body, offset, value)
    struct.pack_into("<I", body, SHARED_CONTROL_COUNT_AT,
                     SHARED_CONTROL_COUNT_AFTER if phase == "after"
                     else SHARED_CONTROL_COUNT_BEFORE)
    struct.pack_into("<Q", body, SHARED_CONTROL_INNER_AT, inner_va)
    iface.writemem(shared_pa, bytes(body))
    p.dc_civac(shared_pa, PAGE)
    uat.iomap_at(context, shared_va, shared_pa, PAGE, **NORMAL_OBJECT_FLAGS)
    arena.entries.append({"name": "shared_control", "va": shared_va,
                          "pa": shared_pa, "size": PAGE})
    print("  shared control at %#x naming %#x" % (shared_va, inner_va))

    channel_pa = alloc_page("channel_control")
    channel_va = CHANNEL_CONTROL_ADDRESS
    body = bytearray(PAGE)
    for record in range(CHANNEL_CONTROL_RECORDS):
        for offset, value in CHANNEL_CONTROL_WORDS:
            struct.pack_into("<Q", body, record * CHANNEL_CONTROL_STRIDE + offset,
                             value)
    iface.writemem(channel_pa, bytes(body))
    p.dc_civac(channel_pa, PAGE)
    uat.iomap_at(context, channel_va, channel_pa, PAGE, **NORMAL_OBJECT_FLAGS)
    arena.entries.append({"name": "channel_control", "va": channel_va,
                          "pa": channel_pa, "size": PAGE})
    item_va = channel_va + CHANNEL_CONTROL_ITEM_RECORD * CHANNEL_CONTROL_STRIDE
    print("  channel control array at %#x, %d records, item names %#x"
          % (channel_va, CHANNEL_CONTROL_RECORDS, item_va))

    state["pointers"] = {
        kind: {
            "context_scratch": state["pages"][kind]["low"],
            "firmware_scratch": state["pages"][kind]["high"],
            "shared_control": shared_va,
            "channel_control": item_va,
        }
        for kind in ("tiling", "fragment")
    }
    uat.flush_dirty()
    return state


def build_descriptor_tails(arena, uat, context, snapshot, render_state,
                           context_state):
    """Extend both work records to full size and redirect everything their tails name.

    The queue parser stops after the register array, so the compact record the builder produces
    is enough for the queue. The context-global locator, which is the address this path writes
    into the optional item's page, reads on past it; a record with nothing there faulted on
    hardware in the replay path, and the fix there was the captured bytes. Same bytes here, with
    every address in them rewritten to name this path's own object rather than the capture's.
    """
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    pages = {}
    for mapping in manifest["mappings"]:
        if mapping.get("blob_index") is not None:
            pages.setdefault(int(mapping["va"]), int(mapping["blob_index"]))
    for group in manifest["root_mappings"]:
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is not None:
                pages.setdefault(int(mapping["va"]), int(mapping["blob_index"]))

    def captured_page(dva):
        index = pages.get(dva & ~(PAGE - 1))
        if index is None:
            raise RuntimeError("no captured page at %#x" % dva)
        return ram[index * PAGE:(index + 1) * PAGE]

    def captured_bytes(dva, size):
        out = b""
        while size:
            body = captured_page(dva)
            start = dva & (PAGE - 1)
            take = min(size, PAGE - start)
            out += body[start:start + take]
            dva += take
            size -= take
        return out

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
                context_state["pointers"]["tiling"]["shared_control"]
                & ~(PAGE - 1))
            continue

        target_va = page_va
        if role == "status":
            # An alias, so the same physical page the render program's status address names.
            target_pa = render_pages[detail]["pa"]
        else:
            target_pa = u.memalign(PAGE, PAGE)
            body = captured_page(page_va) if role == "seed" else bytes(PAGE)
            iface.writemem(target_pa, body)
            p.dc_civac(target_pa, PAGE)
        uat.iomap_at(context, target_va, target_pa, PAGE,
                     AttrIndex=MemoryAttr.Shared, AP=1)
        arena.entries.append({"name": "tail_%s_%#x" % (role, page_va),
                              "va": target_va, "pa": target_pa, "size": PAGE})
        replacement[page_va] = target_va
        print("  %-8s %#-16x -> %#x%s"
              % (role, page_va, target_va,
                 "  (alias of %s)" % detail if role == "status" else ""))
    uat.flush_dirty()

    tails = {}
    for kind, layout in DESCRIPTOR_TAIL.items():
        body = bytearray(captured_bytes(layout["captured"] + layout["built"],
                                        layout["native"] - layout["built"]))
        rewritten = 0
        for offset, value in DESCRIPTOR_TAIL_POINTERS[kind]:
            page_va = value & ~(PAGE - 1)
            if page_va not in replacement:
                raise RuntimeError(
                    "%s tail pointer at +%#x names unlisted page %#x"
                    % (kind, offset, page_va))
            here = offset - layout["built"]
            if struct.unpack_from("<Q", body, here)[0] != value:
                raise RuntimeError(
                    "%s tail at +%#x holds %#x, not the listed %#x"
                    % (kind, offset,
                       struct.unpack_from("<Q", body, here)[0], value))
            target = replacement[page_va] + (value & (PAGE - 1))
            if target != value:
                struct.pack_into("<Q", body, here, target)
                rewritten += 1
        tails[kind] = bytes(body)
        print("  %-8s tail %#x bytes, %d non-zero, %d of %d addresses rewritten"
              % (kind, len(body), sum(byte != 0 for byte in body),
                 rewritten, len(DESCRIPTOR_TAIL_POINTERS[kind])))
    return {"tails": tails, "replacement": replacement}


def write_context_queue_addresses(state, kind, descriptor, queue):
    """Point a kind's context/queue page at the descriptor and queue this path built."""
    pa = state["pages"][kind]["pa"]
    iface.writemem(pa + CONTEXT_QUEUE_DESCRIPTOR_AT, struct.pack("<Q", descriptor))
    iface.writemem(pa + CONTEXT_QUEUE_QUEUE_AT, struct.pack("<Q", queue))
    p.dc_civac(pa, PAGE)
    print("  %-8s context/queue page names descriptor %#x and queue %#x"
          % (kind, descriptor, queue))


def map_full_render_extent(arena, uat, context, snapshot, seeded, seed_all=False):
    """Map every extent the render context has, not only the pages the programs name.

    The register programs name fourteen pages, and mapping exactly those is what this path did.
    The capture's render context is 3,618 pages in 90 contiguous runs totalling 56.5 MiB, and the
    named objects are not single pages: the tile map and heap metadata share a 34-page run, the
    scissor base a 64-page run, the depth-bias base a 48-page run, and there is a 24.4 MiB run at
    `0x10000088000` that nothing in the register programs names at all. A working first render
    writes 917 render pages, 915 of them one contiguous run inside that region, whose content the
    record established is computed rather than copied.

    So the accelerator writes into memory an order of magnitude larger than anything mapped here,
    and a tiler with nowhere to put its output cannot run. This maps the whole extent as fresh zero
    pages and seeds only what the caller already seeds, which keeps the captured content at the
    1,549 input bytes rather than importing the 425 KB the whole context holds.
    """
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    blobs, ptes = {}, {}
    for group in manifest["root_mappings"]:
        if int(group["root_index"]) != RENDER_SNAPSHOT_ROOT:
            continue
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            blobs[int(mapping["va"])] = int(mapping["blob_index"])
            ptes[int(mapping["va"])] = int(mapping["pte"])

    def uxn_of(va):
        return (ptes[va] >> 54) & 1

    addresses = sorted(blobs)
    runs = []
    begin = previous = addresses[0]
    for address in addresses[1:]:
        if address == previous + PAGE and uxn_of(address) == uxn_of(begin):
            previous = address
            continue
        runs.append((begin, previous + PAGE, uxn_of(begin)))
        begin = previous = address
    runs.append((begin, previous + PAGE, uxn_of(begin)))

    if seed_all:
        # Every page of the render context that has content, not only the input objects. The
        # 24.4 MiB run holds 54 KB before any work runs, and this path zeroes it; if the tiler
        # needs an initialised heap there, a zero-filled extent is not enough.
        extra = 0
        for address in addresses:
            if address in seeded:
                continue
            body = ram[blobs[address] * PAGE:(blobs[address] + 1) * PAGE]
            if any(body):
                seeded[address] = body
                extra += sum(byte != 0 for byte in body)
        print("  seeding all render content: %d further pages, %d non-zero bytes"
              % (len(seeded), extra))

    print("Mapping the render context's full extent: %d pages in %d runs, %.1f MiB"
          % (len(addresses), len(runs), len(addresses) * PAGE / float(1 << 20)))
    mapped = {}
    for begin, end, uxn in runs:
        span = end - begin
        pa = u.memalign(PAGE, span)
        # Zeroed on the target rather than by transferring 56 MiB over the proxy.
        p.memset32(pa, 0, span)
        for offset in range(begin, end, PAGE):
            body = seeded.get(offset)
            if body is None:
                continue
            iface.writemem(pa + (offset - begin), body)
        p.dc_civac(pa, span)
        uat.iomap_at(context, begin, pa, span, UXN=uxn, **RENDER_PAGE_FLAGS)
        for offset in range(begin, end, PAGE):
            mapped[offset] = pa + (offset - begin)
        arena.entries.append({"name": "render_extent_%#x" % begin, "va": begin,
                              "pa": pa, "size": span})
    uat.flush_dirty()

    # A head sample of every mapped page, so a scan afterwards can say whether anything in the
    # whole extent changed rather than only whether the fourteen named pages did. The record
    # establishes that the large region a first render writes takes the same 32 bytes in every
    # `0x400` block, so a page's head is enough to catch it.
    heads = {}
    for address in sorted(mapped):
        pa = mapped[address]
        p.dc_civac(pa, PAGE)
        heads[address] = bytes(iface.readmem(pa, 32))
    print("  sampled the head of all %d pages for a whole-extent scan" % len(heads))

    # Every render mapping has been assumed to resolve rather than checked. The accelerator walks
    # these, and a page that translates for the host but not through the context the work names
    # would look exactly like this: work retired, nothing drawn.
    checked = failures = 0
    for address in sorted(mapped)[::37]:
        resolved = uat.iotranslate(context, address, 8)
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

    seeded_here = [address for address in seeded if address in mapped]
    print("  %d runs mapped, %d seeded pages placed inside them"
          % (len(runs), len(seeded_here)))
    missing = sorted(set(seeded) - set(mapped))
    if missing:
        raise RuntimeError("seeded pages outside every run: %s"
                           % ["%#x" % address for address in missing])
    return mapped, heads


def map_firmware_extent(arena, uat, context, snapshot, fill_blank=()):
    """Map every firmware-context page a working host has, blank where the capture has it blank.

    Measured on hardware: zeroing the captured firmware pages the descriptor cannot reach by
    following pointers crashes firmware. And those pages are almost entirely blank, 567 of them
    holding 3,196 non-zero bytes between them, so what firmware needs is that they are **mapped**,
    not what they contain. The same effect was recorded earlier for the secondary's startup, where
    blank native mappings were required beyond the pointer closure.

    This path maps only the objects it builds, so its firmware context has tens of pages where a
    host's has 626. Everything the cold boot has already placed is left alone; this fills in the
    rest of the shape.
    """
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    selected = int(manifest["selected_root"]["index"])
    captured = {}
    for group in manifest["root_mappings"]:
        if int(group["root_index"]) != selected:
            continue
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            captured[int(mapping["va"])] = (int(mapping["blob_index"]),
                                            int(mapping["pte"]))

    already = {}
    for record in arena.entries:
        base = record["va"] & ~(PAGE - 1)
        for offset in range(base, record["va"] + record["size"], PAGE):
            already.setdefault(offset, record["pa"] - (record["va"] - base)
                               + (offset - base))

    # A page this path placed but left blank is not "already provided". The private cluster state
    # region is 1.5 MiB allocated as zeros here, and a working host has thermal and performance
    # configuration in it: floats 100.0 and 400.0, 0.5 and 4.25, and integers 11000, 9900, 8000
    # and 200. Skipping every page this path had placed hid all of it. So for a placed page that is
    # still empty and that the capture has content in, take the content, writing into the page
    # already mapped rather than mapping another over it.
    # Filling all of them at once crashes both instances: those pages hold firmware's own runtime
    # state as well, pointers into the captured world and timestamps, and handing a fresh firmware
    # stale ones is fatal. So this is opt-in per page, which is also what bisecting them needs.
    wanted_blank = {int(value, 0) & ~(PAGE - 1) for value in (fill_blank or ())}
    filled = filled_bytes = 0
    for page_va, page_pa in sorted(already.items()):
        if page_va not in captured or page_va not in wanted_blank:
            continue
        index, _pte = captured[page_va]
        body = ram[index * PAGE:(index + 1) * PAGE]
        if not any(body):
            continue
        # No "only if still blank" guard. The coprocessors start before this runs and firmware
        # writes into its own private cluster region during boot, so the pages this is for are not
        # blank by the time they are looked at, and the guard silently skipped every one of them.
        p.dc_civac(page_pa, PAGE)
        iface.writemem(page_pa, body)
        p.dc_civac(page_pa, PAGE)
        filled += 1
        filled_bytes += sum(byte != 0 for byte in body)
    if filled:
        print("  filled %d pages this path placed and left blank, %d non-zero bytes"
              % (filled, filled_bytes))
    blank_here = sorted(page for page in already
                        if page in captured
                        and any(ram[captured[page][0] * PAGE:
                                    (captured[page][0] + 1) * PAGE]))
    print("  %d pages this path placed have content in the capture: %s"
          % (len(blank_here), ", ".join("%#x" % page for page in blank_here)))

    todo = sorted(address for address in captured if address not in already)
    print("Filling in the firmware context's shape: %d captured pages, %d already placed, "
          "%d to map" % (len(captured), len(captured) - len(todo), len(todo)))

    # Group by contiguity **and** by the captured leaf's attributes. A working host maps most of
    # this context with AttrIndex 0, which m1n1 calls Normal and the device tree describes as
    # accessed only by the coprocessor, fully cached inner and outer; 126 pages with AttrIndex 2,
    # inner non-cacheable; and six of those with UXN clear. This mapped every page AttrIndex 2,
    # so 494 of 626 pages had the wrong cacheability. Firmware reads and writes them either way,
    # which is why nothing failed outright, and coherency with the accelerator does not survive it.
    def attributes_of(va):
        pte = captured[va][1]
        return ((pte >> 2) & 7, (pte >> 54) & 1)

    runs = []
    if todo:
        begin = previous = todo[0]
        for address in todo[1:]:
            if (address == previous + PAGE
                    and attributes_of(address) == attributes_of(begin)):
                previous = address
                continue
            runs.append((begin, previous + PAGE))
            begin = previous = address
        runs.append((begin, previous + PAGE))

    placed = content = 0
    for begin, end in runs:
        span = end - begin
        pa = u.memalign(PAGE, span)
        p.memset32(pa, 0, span)
        for address in range(begin, end, PAGE):
            index, _pte = captured[address]
            body = ram[index * PAGE:(index + 1) * PAGE]
            if any(body):
                iface.writemem(pa + (address - begin), body)
                content += sum(byte != 0 for byte in body)
        p.dc_civac(pa, span)
        attr_index, uxn = attributes_of(begin)
        uat.iomap_at(context, begin, pa, span,
                     AttrIndex=attr_index, AP=1, UXN=uxn)
        arena.entries.append({"name": "firmware_extent_%#x" % begin, "va": begin,
                              "pa": pa, "size": span})
        placed += span // PAGE
    uat.flush_dirty()
    print("  mapped %d pages in %d runs, %d non-zero bytes of content"
          % (placed, len(runs), content))
    return {"captured": len(captured), "already": len(captured) - len(todo),
            "mapped": placed, "runs": len(runs), "content_bytes": content}


def read_render_witness(render_state, label):
    """Read back the objects the accelerator writes when a submission draws.

    Established on hardware: the tiling program's status record and the fragment program's take
    a 16-bit value and a byte each, in the host's own pages. Those two are the witness a cold
    boot can carry, because the large constant region a full render writes lies in pages this
    path does not map.
    """
    print("Render witness %s:" % label)
    state = {}
    for record in render_state["pages"]:
        p.dc_civac(record["pa"], PAGE)
        body = bytes(iface.readmem(record["pa"], PAGE))
        nonzero = sum(byte != 0 for byte in body)
        state[record["name"]] = {
            "nonzero": nonzero,
            "delta": nonzero - record["nonzero"],
            "head": body[:16].hex(),
        }
        if nonzero != record["nonzero"]:
            print("  %-22s %5d -> %-5d non-zero  %s"
                  % (record["name"], record["nonzero"], nonzero, body[:16].hex()))
    unchanged = [name for name, values in state.items() if not values["delta"]]
    print("  %d of %d named pages changed; unchanged: %s"
          % (len(state) - len(unchanged), len(state), ", ".join(sorted(unchanged))))

    # The named pages are fourteen of the 3,618 the extent maps. A submission that executed but
    # wrote somewhere else would leave every one of them alone and look exactly like one that did
    # not execute, so scan the whole extent against the head samples taken when it was mapped.
    extent = render_state.get("extent")
    changed = []
    if extent:
        for address, head in sorted(extent["heads"].items()):
            pa = extent["mapped"][address]
            p.dc_civac(pa, PAGE)
            if bytes(iface.readmem(pa, 32)) != head:
                changed.append(address)
        print("  whole extent: %d of %d mapped pages changed in their first 32 bytes"
              % (len(changed), len(extent["heads"])))
        for address in changed[:20]:
            print("    %#x" % address)
        if len(changed) > 20:
            print("    ... %d more" % (len(changed) - 20))
    state["_extent_changed"] = ["%#x" % address for address in changed]
    return state


def prepare_backend_group(arena, asc, root_va, first_submit=False,
                          render_state=None, context_state=None,
                          tail_state=None):
    """Build and stage a backend group without notifying firmware.

    Firmware refuses a submission naming parameter-buffer state different from the one it has
    bound, and no host structure names that binding, so it is firmware's own. On a cold boot
    nothing has been bound, and this asks whether a group carrying its own state is therefore
    accepted.

    Without ``render_state`` the register arrays are empty and nothing can draw; the signal is
    only whether firmware takes the group. With it, the arrays are the generated programs for a
    render context this path built, so the submission is a rendering test.
    """
    backend = load_backend_modules().g17p_backend

    # The context/queue state, the shared and channel control objects and the descriptor tails'
    # targets all sit at the addresses the capture used, which lie inside the arena's own bump
    # range. Start the heap above all of them rather than racing the cursor.
    if arena.va < BACKEND_HEAP_VA_BASE:
        arena.va = BACKEND_HEAP_VA_BASE
    heap = BackendArena(arena)

    def lookup(dva):
        for entry in arena.entries:
            if entry["va"] <= dva < entry["va"] + entry["size"]:
                return entry["pa"] + (dva - entry["va"])
        return heap.physical(dva)

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

    print("Preparing a backend-built group in cold-booted firmware state")
    channels = backend.G17PChannels(read, root_va)
    named = [entry for entry in channels.entries if entry["name"]]
    print("  channel table: %d entries, %d named" % (len(channels.entries), len(named)))

    builder = backend.G17PPairedWorkBuilder(heap.alloc, heap.write)
    graph = builder.build_submission_graph()
    print("  built its own parameter-buffer state in %d pages" % len(heap.pages))

    # The four optional-item pointers belong to context and queue initialization. Four fresh
    # zero pages here made the scheduler fault on a null dereference at initialisation, so
    # ``context_state`` builds the objects the capture holds instead.
    if context_state is None:
        optional = {kind: {name: heap.alloc(PAGE, "context_%s" % name)
                           for name in ("context_scratch", "firmware_scratch",
                                        "shared_control", "channel_control")}
                    for kind in ("tiling", "fragment")}
        print("  no context/queue state, so the optional items name four empty pages")
    else:
        optional = context_state["pointers"]

    if render_state is None:
        tiling_registers, fragment_registers = [], []
        print("  no render context, so the register arrays are empty and nothing can draw")
    else:
        tiling_registers = render_state["registers"]["tiling"]
        fragment_registers = render_state["registers"]["fragment"]
        print("  register programs: %d tiling writes, %d fragment writes"
              % (len(tiling_registers), len(fragment_registers)))
    pair = builder.item(0, None, tiling_registers, fragment_registers,
                        optional["tiling"], optional["fragment"], 1,
                        tails=None if tail_state is None else tail_state["tails"])
    if tail_state is not None:
        # The tails' self-references name the descriptor through a low alias, so the descriptor's
        # own pages have to be mapped there as well. Same physical pages, second device address,
        # with the low region's attributes.
        for kind, low in DESCRIPTOR_LOW_ALIAS.items():
            descriptor = pair[kind][0]
            base = descriptor & ~(PAGE - 1)
            span = (((descriptor - base)
                     + DESCRIPTOR_TAIL[kind]["native"]) + PAGE - 1) & ~(PAGE - 1)
            base_pa = heap.physical(base)
            if base_pa is None:
                raise RuntimeError("no physical page for the %s descriptor" % kind)
            arena.uat.iomap_at(arena.ctx, low, base_pa, span, **LOW_ALIAS_FLAGS)
            arena.entries.append({"name": "%s_descriptor_low_alias" % kind,
                                  "va": low, "pa": base_pa, "size": span})
            print("  %-8s descriptor %#x aliased at %#x, %#x bytes"
                  % (kind, descriptor, low + (descriptor - base), span))
        arena.uat.flush_dirty()
        arena.uat.invalidate_cache()

    print("  TA %s" % ["%#x" % value for value in pair["tiling"]])
    print("  3D %s" % ["%#x" % value for value in pair["fragment"]])

    submitter = backend.G17PSubmitter(
        read, write, lambda: asc.db.send(
            DoorbellMsg(TYPE=g17p.MSG_WORK_DOORBELL, CHANNEL=0)), channels)
    staged = {}
    created_queues = []
    queue_of = {}
    grid_of = {}
    # A working host's two queue records are adjacent in one `0xc0`-stride array, and the closure
    # walk reaches the second only by stepping `0xc0` from the first. Separate allocations leave
    # that step landing in zeroes, so the second queue is unreachable from the descriptor graph
    # even though its own channel names it. One array, two slots.
    queue_array = heap.alloc(2 * g17p.QUEUE_RECORD_STRIDE, "queue_record_array")
    # A working host's two queues of a pair name **one** job list, not one each. The list is
    # intrusive and the scheduler links work onto it, so two lists means the pair's halves are on
    # separate lists and neither can see the other's half.
    # One low-region page holds both queues' pointer blocks, on the per-queue stride, which is
    # where a working host keeps them rather than with the submission objects.
    arena.alloc_at(QUEUE_POINTER_BLOCK_VA, PAGE, "queue_pointer_blocks_and_job_list")
    # Both queues of a pair share one job list and a working host keeps it in the low region, not
    # with the submission objects. The list is intrusive, so it names its own address.
    shared_job_list = QUEUE_JOB_LIST_VA
    write(shared_job_list, g17p.build_job_list(shared_job_list))
    print("  one job list at %#x for both queues of the pair" % shared_job_list)
    # The grid index and the kind are both carried by the ring slot, and both were wrong here. A
    # captured world puts the first tiling channel's queue at grid index 0 and the first fragment
    # channel's at 1, and a fragment channel whose slot lacks the kind word does not accept a
    # publication at all. Neither was known when this path last reported that firmware serviced
    # nothing.
    for name, kind, grid_index in (("TA_0", "tiling", 0), ("3D_0", "fragment", 1)):
        entry = channels.by_name(name)
        if entry is None:
            print("  channel %s is absent from the table" % name)
            continue
        queue_addr = struct.unpack("<Q", read(entry["ring_addr"] + 8, 8))[0]
        if not queue_addr:
            # Nothing has ever created a queue on this path, so build one. The record's
            # layout is decoded and gated offline; what is untested is firmware accepting
            # a queue it did not see a captured host create.
            # In the low region, on the per-queue stride, not in the heap. See
            # QUEUE_POINTER_BLOCK_VA: a working host keeps both blocks in one low-region page
            # 0x2870 apart, with the roots and channel state rather than the submission objects.
            queue_pointers = (QUEUE_POINTER_BLOCK_VA
                              + len(created_queues) * QUEUE_POINTER_BLOCK_STRIDE)
            write(queue_pointers, g17p.build_queue_pointers())
            item_ring = heap.alloc(PAGE, "%s_item_ring" % name)
            heap.write(item_ring, bytes(PAGE))
            job_list = shared_job_list
            # The queue record's context object is the **same object** the optional items name
            # as their channel control: a working host has both queues' context field and both
            # optional items' `+0x4a` all holding `0xfffffc20c07b8040`, the channel control array's
            # second record. This path built three separate objects for one, which is the same
            # fault as the shared control object being built twice.
            if context_state is None:
                context_object = heap.alloc(PAGE, "%s_queue_context" % name)
                heap.write(context_object, bytes(PAGE))
            else:
                context_object = context_state["pointers"][kind]["channel_control"]
            queue_addr = queue_array + len(created_queues) * g17p.QUEUE_RECORD_STRIDE
            heap.write(queue_addr, g17p.build_queue_record(
                pointers_addr=queue_pointers, ring_addr=item_ring,
                job_list_addr=job_list, context_addr=context_object,
                uuid=QUEUE_UUID_VALUE))
            write(entry["ring_addr"] + g17p.RING_SLOT_QUEUE_PTR,
                  struct.pack("<Q", queue_addr))
            created_queues.append({"channel": name, "queue": queue_addr,
                                   "pointers": queue_pointers, "ring": item_ring,
                                   "job_list": job_list,
                                   "context": context_object})
            print("  created a %s queue at %#x (pointers %#x, ring %#x)"
                  % (name, queue_addr, queue_pointers, item_ring))
        if context_state is not None:
            # The page each optional item names carries its kind's descriptor and queue
            # addresses. Both exist only now, so this is where they are written.
            write_context_queue_addresses(
                context_state, kind, pair[kind][0], queue_addr)
        queue = backend.G17PQueue(read, queue_addr, grid_index)
        queue_of[name] = queue_addr
        grid_of[name] = grid_index
        staged[name] = submitter.stage(
            entry, queue, pair[kind], 1, slot=0 if first_submit else None,
            first_submit=first_submit, kind=kind,
            event_subtype=(g17p.EVENT_SUBTYPE_BASE | grid_index
                           if first_submit else None))
    counters_before = {}
    for name in staged:
        entry = channels.by_name(name)
        counters_before[name] = [
            struct.unpack("<I", read(addr, 4))[0] for addr in entry["state_addrs"][:3]]

    # The channel counters say firmware took the entries off the ring. The queue's done index
    # is the completion witness, and the two come apart: a republished group is accepted and
    # its read index advances while its done index never moves. Both are recorded, and the
    # heap is sampled so a run can also say what firmware wrote back.
    queues = {name: backend.G17PQueue(read, queue_of[name], grid_of[name])
              for name in staged}
    indices_before = {name: queues[name].indices() for name in staged}
    heap_before = {}
    for va, pa, size in heap.pages:
        p.dc_civac(pa, size)
        heap_before[va] = bytes(iface.readmem(pa, size))

    # The queue records and item rings are AttrIndex 0 in a working host's tables and this heap
    # is mapped Shared like the rest of the arena. Remap every page it took.
    for heap_va, heap_pa, heap_size in heap.pages:
        arena.uat.iomap_at(arena.ctx, heap_va, heap_pa, heap_size,
                              **NORMAL_OBJECT_FLAGS)
    arena.uat.flush_dirty()
    arena.uat.invalidate_cache()
    print("  remapped %d heap pages as Normal, matching a working host's queue and ring leaves"
          % len(heap.pages))

    print("  staged %s; doorbell deferred"
          % (", ".join(sorted(staged)) if staged else "nothing"))
    for name in sorted(staged):
        print("    %s queue indices %s" % (name, indices_before[name]))
    return {
        "asc": asc,
        "channels": channels,
        "submitter": submitter,
        "read": read,
        "staged": staged,
        "counters_before": counters_before,
        "queues": queues,
        "indices_before": indices_before,
        "heap_before": heap_before,
        "created_queues": created_queues,
        "heap": heap,
        "graph": graph,
        "first_submit": bool(first_submit),
    }


def finish_backend_group(prepared):
    """Notify firmware about a prepared backend group and report consumption."""
    asc = prepared["asc"]
    channels = prepared["channels"]
    submitter = prepared["submitter"]
    read = prepared["read"]
    staged = prepared["staged"]
    counters_before = prepared["counters_before"]
    if staged:
        submitter.notify()
        print("  rang the work doorbell")
    else:
        print("  nothing staged, so no doorbell")

    # Whether firmware did anything with it. The counters are the same three this record
    # has used throughout, and a run that publishes without checking them says nothing.
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
    print("  firmware events seen: %d" % asc.fw.events)

    # Completion, separately from consumption. Whether the done index reaches the write index
    # is the witness this project settled on, because acceptance moves the read index on its
    # own and says nothing about the work running.
    indices = {}
    for name in sorted(staged):
        before = prepared["indices_before"][name]
        after = prepared["queues"][name].indices()
        indices[name] = {"before": before, "after": after}
        print("  %s queue indices %s -> %s  %s"
              % (name, before, after,
                 "completed" if after.get("done", 0) >= after.get("write", 1)
                 and after.get("write") else "not completed"))

    # What firmware wrote into the objects this path handed it. A run that reports only
    # counters cannot distinguish firmware ignoring the group from firmware working on it.
    written = {}
    for va, pa, size in prepared["heap"].pages:
        p.dc_civac(pa, size)
        now = bytes(iface.readmem(pa, size))
        was = prepared["heap_before"].get(va)
        if was is None or now == was:
            continue
        differing = sum(a != b for a, b in zip(was, now))
        first = next(index for index in range(len(now)) if now[index] != was[index])
        written["%#x" % va] = {"bytes": differing, "first": first}
        print("  firmware wrote %d bytes into heap page %#x, first at +%#x"
              % (differing, va, first))
    if not written:
        print("  firmware wrote nothing into any of the %d heap pages"
              % len(prepared["heap"].pages))

    return {"pages": len(prepared["heap"].pages), "staged": sorted(staged),
            "created_queues": prepared["created_queues"], "consumed": consumed,
            "events": asc.fw.events, "indices": indices, "heap_written": written,
            "graph_pages": len(prepared["graph"].get("pages", {})),
            "first_submit": prepared["first_submit"]}


def publish_backend_group(arena, asc, root_va, args):
    """Prepare, notify, and measure a backend group after initdata acknowledgement."""
    del args
    return finish_backend_group(
        prepare_backend_group(arena, asc, root_va, first_submit=False))


def dump_initdata_closure(uat, context, init_va, out_dir):
    """Walk firmware-context pointers transitively from initdata and save what is reachable.

    The same worklist the snapshot side uses, so the two are comparable. A reference into an
    unmapped page is recorded rather than skipped: the snapshot's closure has none, so any here
    is a difference worth seeing.
    """
    FW_TAG = 0xFFFFFC20
    base = init_va & ~(PAGE - 1)
    seen = {base}
    pending = [base]
    contents = {}
    unmapped = {}
    rounds = 0
    while pending and len(seen) < 512:
        rounds += 1
        frontier, pending = pending, []
        for page_va in frontier:
            try:
                body = uat.ioread(context, page_va, PAGE)
            except Exception:
                continue
            contents[page_va] = bytes(body)
            for offset in range(0, PAGE - 8, 8):
                word = struct.unpack_from("<Q", body, offset)[0]
                if (word >> 32) != FW_TAG:
                    continue
                target = word & ~(PAGE - 1)
                if target in seen:
                    continue
                try:
                    uat.ioread(context, target, 8)
                except Exception:
                    unmapped.setdefault(target, []).append((page_va, offset))
                    continue
                seen.add(target)
                pending.append(target)

    path = out_dir / "initdata_closure.json"
    path.write_text(json.dumps({
        "init_va": int(init_va),
        "rounds": rounds,
        "pages": sorted(seen),
        "unmapped": {("%#x" % k): v for k, v in unmapped.items()},
    }, indent=2, sort_keys=True) + "\n")
    (out_dir / "initdata_closure.bin").write_bytes(
        b"".join(contents[page] for page in sorted(contents)))
    print("  closure: %d pages in %d rounds, %d references into unmapped pages"
          % (len(seen), rounds, len(unmapped)))
    for target, refs in sorted(unmapped.items())[:8]:
        page_va, offset = refs[0]
        print("     unmapped %#014x referenced from %#014x+%#x" % (target, page_va, offset))
    return {"pages": sorted(seen), "unmapped": sorted(unmapped)}


def seed_native_pages(uat, context, snapshot, dvas):
    """Replace selected coldboot pages with pre-init hardware-captured bytes."""
    snapshot = pathlib.Path(snapshot)
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    selected = int(manifest["selected_root"]["index"])
    va_mask = (1 << 44) - 1
    mappings = {
        int(mapping["va"]) & va_mask: mapping
        for group in manifest["root_mappings"]
        if int(group["root_index"]) == selected
        for mapping in group["mappings"]
        if mapping.get("blob_index") is not None
    }
    records = []
    for raw_dva in dvas:
        dva = int(raw_dva) & ~(PAGE - 1)
        mapping = mappings.get(dva & va_mask)
        if mapping is None:
            raise RuntimeError(
                "native snapshot has no captured selected-root page at %#x" % dva
            )
        index = int(mapping["blob_index"])
        native = ram[index * PAGE:(index + 1) * PAGE]
        before = bytes(uat.ioread(context, dva, PAGE))
        uat.iowrite(context, dva, native)
        for pa, size in uat.iotranslate(context, dva, PAGE):
            if pa is None:
                raise RuntimeError("coldboot page %#x became unmapped" % dva)
            p.dc_civac(pa, size)
        after = bytes(uat.ioread(context, dva, PAGE))
        if after != native:
            raise RuntimeError("native page seed did not survive at %#x" % dva)
        differing = sum(a != b for a, b in zip(before, native))
        runs = []
        start = None
        for offset, (cold_byte, native_byte) in enumerate(zip(before, native)):
            if cold_byte != native_byte:
                if start is None:
                    start = offset
            elif start is not None:
                runs.append({
                    "offset": start,
                    "cold": before[start:offset].hex(),
                    "native": native[start:offset].hex(),
                })
                start = None
        if start is not None:
            runs.append({
                "offset": start,
                "cold": before[start:].hex(),
                "native": native[start:].hex(),
            })
        records.append(
            {
                "dva": dva,
                "snapshot_pa": int(mapping["pa"]) & ~(PAGE - 1),
                "differing_bytes": differing,
                "difference_runs": runs,
            }
        )
        print("  seeded native page %#x (%d bytes changed)" % (dva, differing))
    return records


def coproc_maintain_pages(uat, arena, context, handoff_base, secondary_root=None):
    """Publish every host-created data/UAT page through the coprocessor path."""
    pages = {handoff_base & ~(PAGE - 1),
             uat.gpu_region & ~(PAGE - 1),
             uat.ttbr0_base & ~(PAGE - 1),
             uat.ttbr1_base & ~(PAGE - 1)}
    if secondary_root is not None:
        pages.add(secondary_root & ~(PAGE - 1))

    for record in arena.entries:
        start = record["pa"] & ~(PAGE - 1)
        end = (record["pa"] + record["size"] + PAGE - 1) & ~(PAGE - 1)
        pages.update(range(start, end, PAGE))

    def add_table(_start, _end, _index, pte, _level, sparse=False):
        del sparse
        pages.add(int(pte.offset()) & ~(PAGE - 1))

    uat.foreach_table(context, add_table)

    op = (
        "mov x8, x0; dsb osh; sys #3, c7, c3, #4, x8; "
        "sys #3, c7, c3, #5, x8; dsb osh; isb"
    )
    print("  coprocessor-maintaining %d host data/UAT pages" % len(pages))
    for page in sorted(pages):
        p.dc_civac(page, PAGE)
        u.inst(op, page)
    return sorted(pages)


def initialize_uat_preserving_shared_root(uat):
    """Initialize host UAT bookkeeping without clearing firmware-owned root slots."""
    if uat.initialized:
        return
    uat.handoff.initialize()
    with uat.handoff.lock():
        uat.set_l0(0, 0, uat.ttbr0_base)
        uat.set_l0(0, 1, uat.ttbr1_base)
        uat.flush_dirty()
        uat.invalidate_cache()
    uat.initialized = True


def snapshot_arena(arena):
    """Every object handed to firmware, read back in bulk."""
    return {record["name"]: bytes(iface.readmem(record["pa"], record["size"]))
            for record in arena.entries}


def diff_snapshots(before, after, label):
    """Report which objects firmware wrote to, and where."""
    changes = []
    for name, first in before.items():
        second = after[name]
        if first == second:
            continue
        spans = []
        start = None
        for i in range(len(first)):
            if first[i] != second[i]:
                if start is None:
                    start = i
            elif start is not None:
                spans.append((start, i))
                start = None
        if start is not None:
            spans.append((start, len(first)))
        changes.append((name, spans, first, second))

    if not changes:
        print("  %s: firmware touched none of the memory it was handed" % label)
        return changes

    print("  %s: firmware touched %d objects" % (label, len(changes)))
    for name, spans, first, second in changes:
        total = sum(b - a for a, b in spans)
        print("    %-22s %d bytes in %d runs" % (name, total, len(spans)))
        for a, b in spans[:6]:
            print("      %#06x..%#06x  was %s  now %s"
                  % (a, b, first[a:b].hex(), second[a:b].hex()))
    return changes


def blank_perf_tables():
    """Performance tables with the shape firmware expects and no real values.

    Whether firmware needs meaningful frequencies to accept a descriptor is exactly
    the sort of question this experiment can answer, so they start empty and are
    filled in only if that turns out to matter.
    """
    return {
        "freq_a": [0] * build.LADDER_ENTRIES,
        "freq_b": [0] * build.LADDER_ENTRIES,
        "scale_b": [0] * build.LADDER_ENTRIES,
        "relative_a": [0] * build.LADDER_ENTRIES,
        "relative_b": [0] * build.LADDER_ENTRIES,
        "index_a": list(range(build.LADDER_ENTRIES)),
        "index_b": list(range(build.LADDER_ENTRIES)),
        "core_voltage": [0] * build.LADDER_ENTRIES,
        "memory_voltage": [0] * build.LADDER_ENTRIES,
        "voltage_repeat": 16,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=lambda v: int(v, 0), default=1,
                        help="translation context to bind; must not be 0")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--private-upper-root", action="store_true",
                        help="build mappings in a private copy of the upper root table")
    parser.add_argument("--preserve-shared-root", action="store_true",
                        help="do not clear pre-existing firmware upper-root entries "
                             "during host UAT initialization")
    parser.add_argument("--control-channel", type=lambda v: int(v, 0),
                        default=g17p.CONTROL_START_CHANNEL,
                        help="doorbell channel number for device control")
    parser.add_argument("--sweep-control", type=lambda v: int(v, 0), default=0,
                        help="ring every doorbell number below this and report")
    parser.add_argument("--dump-closure", action="store_true",
                        help="walk every page firmware can reach from initdata and save it, for "
                             "comparison against a snapshot's closure")
    parser.add_argument("--dump-state", action="store_true",
                        help="read back what firmware wrote after acknowledging")
    parser.add_argument("--control-type", type=lambda v: int(v, 0),
                        default=g17p.MSG_CONTROL_START,
                        help="message type used to notify the control channel")
    parser.add_argument("--instances", type=int, default=1,
                        help="how many firmware instances to bring up; the second "
                             "is not started by default")
    parser.add_argument("--start-secondary-first", action="store_true",
                        help="start gfx1-asc before gfx-asc while retaining the "
                             "normal primary/secondary descriptor order")
    parser.add_argument("--single-context", dest="bind_all", action="store_false",
                        help="bind only the chosen context, not all of them")
    parser.add_argument("--mirror-context-zero", action="store_true",
                        help="also bind the constructed mapping into raw context 0")
    parser.add_argument("--verbose-asc", type=int, default=0,
                        help="log coprocessor traffic; firmware may be saying "
                             "something that is currently being discarded")
    parser.add_argument("--settle", type=float, default=0.0,
                        help="seconds to let firmware run after it acknowledges, "
                             "before the start notification")
    parser.add_argument("--notify-repeat", type=int, default=1,
                        help="send the start notification this many times")
    parser.add_argument("--probe-endpoint", action="store_true",
                        help="send an unknown message type to the doorbell "
                             "endpoint to see whether it is alive")
    parser.add_argument("--also-notify", action="store_true",
                        help="follow the opening kick with the per-publish "
                             "notification, as a live system does")
    parser.add_argument("--seed-fixed-regions", metavar="SNAPSHOT",
                        nargs="?", const=str(g17p.FIXED_REGION_SNAPSHOT),
                        help="restore the accelerator's device-tree carveouts from a "
                             "snapshot before starting anything. This script has only "
                             "ever written the handoff one; firmware maps the shared "
                             "region itself and this host leaves it zero")
    parser.add_argument("--dump-post-ack", action="store_true",
                        help="save the five top-level descriptor objects in full after "
                             "acknowledgement, so what firmware wrote can be diffed against a "
                             "working world's rather than only the two worlds' inputs")
    parser.add_argument("--fill-blank-page", action="append", default=[],
                        metavar="DVA",
                        help="with --firmware-extent, fill this page, which this path placed "
                             "and left blank, with the capture's content. Repeatable. Filling "
                             "all such pages at once crashes both instances, because they hold "
                             "firmware's own runtime state as well as host configuration")
    parser.add_argument("--seed-report-channels", action="store_true",
                        help="give the firmware-produced channels the counters they carry in "
                             "the world that renders, channel 13 at (1, 13, 0) and channel 14 "
                             "at (8, 5, 0), rather than starting every counter at zero")
    parser.add_argument("--shared-control-phase", choices=("before", "after"),
                        default="before",
                        help="which side of the first 0x20 to build the shared control object "
                             "on. The only world observed to render is on the after side: its "
                             "cursor reads 0xb0 and its inner byte 2, so its firmware inherited "
                             "the operation's result rather than performing it, which is what "
                             "this path's firmware declines to do")
    parser.add_argument("--presume-control-consumed", action="store_true",
                        help="set the device-control channel's consumer counters to the "
                             "producer before initdata, so firmware processes no opening "
                             "entry. This is the state the only world observed to render is "
                             "in: its counters read [4, 4, 4] before the initial kick")
    parser.add_argument("--seed-fixed-region", action="append", default=[],
                        metavar="NAME",
                        help="with --seed-fixed-regions, seed exactly these carveouts by name "
                             "instead of the default seedable set; repeatable")
    parser.add_argument("--sweep-types",
                        type=lambda v: [int(x, 0) for x in v.split(",")],
                        default=None,
                        help="send these message types in order on the doorbell "
                             "endpoint and report which moves a counter or changes "
                             "memory. Order matters: firmware faults on a type it "
                             "does not recognise and a fault ends the boot, so put "
                             "the plausible ones first and treat reaching the end "
                             "as the interesting outcome")
    parser.add_argument("--stage-work", type=int, default=None,
                        help="also publish on this work channel and ring its "
                             "doorbell, to test whether the scheduler scans the "
                             "control ring only while doing a work pass")
    parser.add_argument("--start-smc", action="store_true",
                        help="complete the management coprocessor's handshake before "
                             "starting the graphics coprocessors, since the graphics "
                             "firmware's power tasks may expect it to be serviced")
    parser.add_argument("--scan-mailboxes", action="store_true",
                        help="scan the coprocessor control block for a mailbox the "
                             "host does not use, which the scheduler's unanswered "
                             "peer message should leave reporting non-empty")
    parser.add_argument("--no-state-ptr", action="store_true",
                        help="leave the bundle state pointer clear instead of "
                             "pointing it at a host allocation; a running native "
                             "firmware holds an address there from its own private "
                             "range, not from the region host objects live in")
    parser.add_argument("--answer-23", type=lambda v: int(v, 0), action="append",
                        help="after the notification, send this payload back to the "
                             "peer endpoint the scheduler messages and gets no "
                             "answer to; repeatable to try several replies")
    parser.add_argument("--full-control", action="store_true",
                        help="stage the four device-control entries a host publishes, three "
                             "carrying opcode 0x16 and one carrying 0x20 with its configuration "
                             "object, instead of the single 0x16 this path has always sent")
    parser.add_argument("--defer-full-control", action="store_true",
                        help="with --full-control, hand over only the opening entry "
                             "and stage entries 1-3 after both opening consumers "
                             "advance, as the native sequence does")
    parser.add_argument("--control-opcode", type=lambda v: int(v, 0), default=None,
                        help="override the staged device-control entry opcode on "
                             "every instance; use an invalid value to test whether "
                             "firmware acts on the entry content at all")
    parser.add_argument("--native-kick", action="store_true",
                        help="ring the two doorbells a live host rings, in the "
                             "order its own mailbox log records: the control "
                             "kick carrying the control channel, then a work "
                             "doorbell for channel zero")
    parser.add_argument("--crash-at", choices=("after-ack", "after-notify"),
                        help="provoke a fault at this point and read the report, "
                             "to compare firmware internal state either side of "
                             "the start notification")
    parser.add_argument("--state-after-control", action="store_true",
                        help="place the bundle state object at the fixed "
                             "offset above the secondary control state that "
                             "a native capture shows, not on its own page")
    parser.add_argument("--read-crash", action="store_true",
                        help="read the firmware crash report when a fault occurs, "
                             "so the fault can be located")
    parser.add_argument("--reaction", action="store_true",
                        help="diff every object handed to firmware across the "
                             "start notification")
    parser.add_argument("--registers", action="store_true",
                        help="read the accelerator registers a live capture also "
                             "reads, for comparison")
    parser.add_argument("--live-root-offset", type=lambda v: int(v, 0), default=0,
                        help="place the descriptor roots at this offset from the "
                             "region base, as a working host does (0x1a8000)")
    parser.add_argument("--native-root-neighbors", action="store_true",
                        help="place region_c/root0/root1/region_a at the native "
                             "0x8000-stride addresses; requires --live-root-offset")
    parser.add_argument("--native-object-attrs", action="store_true",
                        help="use the native Normal/Shared and UXN split for "
                             "descriptor object mappings")
    parser.add_argument("--native-channel-state-layout", action="store_true",
                        help="preserve native status/channel-state pointer aliases "
                             "and the non-linear work-state order")
    parser.add_argument("--native-memory-layout", action="store_true",
                        help="place the full confirmed descriptor graph at its "
                             "native high/low DVA relationships")
    parser.add_argument("--no-primary-status-extra", action="store_true",
                        help="leave primary status_a +0x10/+0x14 zero, as in "
                             "the pre-init native image")
    parser.add_argument("--secondary-root-extra",
                        choices=("auto", "none", "first", "second", "both"),
                        default="auto",
                        help="populate either or both observed secondary-only "
                             "root pointers at +0xb8/+0xc0; auto uses both for "
                             "the native memory layout and none otherwise")
    parser.add_argument("--secondary-root-extra-first-dva",
                        type=lambda value: int(value, 0), metavar="DVA",
                        help="override the secondary root +0xb8 pointer for a "
                             "relocation experiment; the DVA must already be mapped")
    parser.add_argument("--seed-native-page", action="append", default=[],
                        type=lambda value: int(value, 0), metavar="DVA",
                        help="replace this mapped 16 KiB coldboot page with its "
                             "pre-init captured bytes; repeatable")
    parser.add_argument("--seed-native-page-snapshot", type=pathlib.Path,
                        default=DEFAULT_NATIVE_SNAPSHOT, metavar="SNAPSHOT",
                        help="snapshot supplying --seed-native-page bytes")
    parser.add_argument("--post-ack-observe-ms", type=float, default=0.0,
                        help="poll both instances for this many milliseconds after "
                             "all init acknowledgements, before any control start")
    parser.add_argument("--hwdata-offset", type=lambda v: int(v, 0),
                        default=0x10000000,
                        help="place hardware-data allocations at this offset from "
                             "the firmware region base; native T8140 uses "
                             "0xc0788000")
    parser.add_argument("--native-main-dvas", action="store_true",
                        help="place the primary and secondary main configuration "
                             "objects at their observed native subpage DVAs")
    parser.add_argument("--coproc-maint", action="store_true",
                        help="publish every host-created data and UAT page through "
                             "the EL2-accessible coprocessor maintenance SYS pair")
    parser.add_argument("--build-before-run", action="store_true",
                        help="construct and bind the UAT, initdata, and initial "
                             "control rings before releasing either ASC")
    parser.add_argument("--secondary-only", action="store_true",
                        help="start both coprocessors but give a descriptor only "
                             "to the second")
    parser.add_argument("--iop-power", action="store_true",
                        help="also send the coprocessor power-state request the "
                             "generic path sends and a live host does not")
    parser.add_argument("--blank-perf", action="store_true",
                        help="zero the performance tables instead of using the "
                             "recorded ladders")
    parser.add_argument("--bundle-word-b75c", type=lambda v: int(v, 0),
                        help="override the variable u32 at hardware-data bundle "
                             "+0xb75c for an exact-content experiment")
    parser.add_argument("--init-instances", type=int, default=0,
                        help="how many of the started instances are given a "
                             "descriptor; 0 means all of them")
    parser.add_argument("--stage-control-instances", type=int, default=0,
                        help="how many instances receive a staged control entry "
                             "before initdata; 0 means all of them")
    parser.add_argument("--control-start-instances", type=int, default=0,
                        help="how many initialized instances receive the initial "
                             "control-start doorbell; 0 means all of them")
    parser.add_argument("--control-start-offset", type=int, default=0,
                        help="zero-based initialized-instance offset at which to "
                             "begin the control-start subset")
    parser.add_argument("--control-start-order", metavar="INDICES",
                        help="comma-separated initialized-instance indices for "
                             "the initial control-start doorbells; overrides "
                             "--control-start-offset/--control-start-instances")
    parser.add_argument("--control-start-gap-ms", type=float, default=0.0,
                        help="delay between initial control-start doorbells; "
                             "the default remains immediate back-to-back sends")
    parser.add_argument("--post-control-start-observe-ms", type=float,
                        default=0.0,
                        help="poll every initialized ASC for this many milliseconds "
                             "after the initial control-start subset")
    parser.add_argument("--stop-after-control-start", action="store_true",
                        help="write the post-control-start observation and exit "
                             "without sending any later device-control doorbell")
    parser.add_argument("--serialise-init", action="store_true",
                        help="wait for each instance to acknowledge before giving "
                             "the next one its descriptor")
    parser.add_argument("--native-sequence", action="store_true",
                        help="use the observed native ASC management ordering and "
                             "start graphics endpoints immediately before each "
                             "instance receives initdata")
    parser.add_argument("--no-control", action="store_true",
                        help="stop after the descriptor is acknowledged")
    parser.add_argument("--patch-hwdata", action="append", default=[],
                        type=lambda v: (int(v.split("=")[0], 0),
                                       int(v.split("=")[1], 0)),
                        metavar="OFFSET=VALUE",
                        help="write a u32 into the hardware-data bundle before "
                             "firmware reads it; repeatable")
    parser.add_argument("--patch-data-region", action="append", default=[],
                        type=lambda v: (int(v.split("=")[0], 0),
                                       int(v.split("=")[1], 0)),
                        metavar="OFFSET=VALUE",
                        help="write a u32 into the descriptor's data region before "
                             "firmware reads it; repeatable. For the fields a working "
                             "host sets and this path leaves zero")
    parser.add_argument("--full-secondary-control", action="store_true",
                        help="stage the second instance's whole opening sequence, three 0x2a "
                             "entries then thirteen 0x22, which is what a working world's own "
                             "control ring holds and what its counters read, rather than the "
                             "single 0x2a this path has always sent")
    parser.add_argument("--patch-status-a", action="append", default=[],
                        type=lambda v: (int(v.split("=")[0], 0),
                                        int(v.split("=")[1], 0)),
                        metavar="OFFSET=VALUE",
                        help="write a u32 into the channel-state block the root reaches at "
                             "+0xa8 before firmware reads it; repeatable. This block is "
                             "upstream of the register array and so still in scope")
    parser.add_argument("--patch-main-config", action="append", default=[],
                        type=lambda v: (int(v.split("=")[0], 0),
                                        int(v.split("=")[1], 0)),
                        metavar="OFFSET=VALUE",
                        help="write a u32 into the main configuration object before "
                             "firmware reads it; repeatable. For the words a working host "
                             "sets there that are not addresses and so cannot be found by "
                             "walking the descriptor graph")
    parser.add_argument("--publish-backend-group", action="store_true",
                        help="after acknowledgement, have the DRM backend build a "
                             "group carrying its own parameter-buffer state and "
                             "publish it. Tests whether firmware that has bound "
                             "nothing accepts one")
    parser.add_argument("--prestage-backend-group", action="store_true",
                        help="create queues and stage the backend group before "
                             "initdata, then notify after opening control")
    parser.add_argument("--seed-render-content", action="store_true",
                        help="with --full-render-extent, seed every render page that has "
                             "content rather than only the input objects. The 24.4 MiB run "
                             "holds 54 KB before any work runs and this path zeroes it")
    parser.add_argument("--prefill-operand-entry", action="store_true",
                        help="write the operand table's entry at +0x440 rather than leaving the "
                             "table empty as the capture has it before the first 0x20. An empty "
                             "slot is the obvious candidate for the null pointer the 0x20 handler "
                             "writes through when the channel producers are set")
    parser.add_argument("--native-context-split", action="store_true",
                        help="with --native-context-slots, also leave the firmware slot without "
                             "a low-address root and the render slot without a high one, which "
                             "is how a working host's root table reads: the firmware context is "
                             "the only one of the twelve with root0 zero")
    parser.add_argument("--native-context-slots", action="store_true",
                        help="arrange the translation root table as a working host does: the "
                             "firmware context at slot 1 tagged 64 and the render context at "
                             "slot 7 tagged 1, so the context id a work item names does not "
                             "resolve to the slot firmware itself runs in")
    parser.add_argument("--firmware-extent", metavar="SNAPSHOT", nargs="?",
                        type=pathlib.Path, const=DEFAULT_RENDER_SNAPSHOT,
                        help="map every firmware-context page a working host has, blank where "
                             "the capture has it blank. Zeroing the captured pages the "
                             "descriptor cannot reach crashes firmware, and those pages are "
                             "almost entirely blank, so what is needed is that they are mapped")
    parser.add_argument("--full-render-extent", action="store_true",
                        help="map every extent the capture's render context has, 3,618 pages "
                             "in 90 runs and 56.5 MiB, as fresh zero pages, rather than only "
                             "the fourteen pages the register programs name. A working first "
                             "render writes 917 render pages, 915 of them one contiguous run "
                             "inside a 24.4 MiB region nothing in the programs names")
    parser.add_argument("--seed-context-queue", metavar="SNAPSHOT", nargs="?",
                        type=pathlib.Path, const=DEFAULT_RENDER_SNAPSHOT,
                        help="fill both context/queue pages with the captured bytes rather "
                             "than the modelled words, keeping this path's own descriptor "
                             "and queue addresses; a bisect for whether the built content "
                             "is what stops the work executing")
    parser.add_argument("--control-tick-before", type=int, default=0,
                        help="publish this many opcode-0x2e device-control entries before "
                             "the work doorbell, which is what a booted host does "
                             "continuously while it submits work")
    parser.add_argument("--control-tick-after", type=int, default=0,
                        help="publish this many opcode-0x2e device-control entries after "
                             "the work doorbell")
    parser.add_argument("--descriptor-tails", metavar="SNAPSHOT", nargs="?",
                        type=pathlib.Path, const=DEFAULT_RENDER_SNAPSHOT,
                        help="extend both work records to full size with the bytes past "
                             "the register array, redirecting every address in them to "
                             "this path's own objects; the context-global descriptor "
                             "view reads past the compact body the queue parser stops at")
    parser.add_argument("--context-queue-state", action="store_true",
                        help="build the context and queue state a first-work optional "
                             "item names, rather than handing it four empty pages")
    parser.add_argument("--render-context", metavar="SNAPSHOT", nargs="?",
                        type=pathlib.Path, const=DEFAULT_RENDER_SNAPSHOT,
                        help="build the render context a verified submission draws in, "
                             "generating the tiler stream and the scissor record and "
                             "seeding from SNAPSHOT only the content this project cannot "
                             "generate; without this the staged group has empty register "
                             "arrays and cannot draw")
    parser.add_argument("--handoff", action="store_true",
                        help="use the firmware translation-table handoff protocol")
    parser.add_argument("--capture-pre-run-state", action="store_true",
                        help="capture safe GPU data/shared state after power and "
                             "AXI setup, then exit before starting either ASC")
    parser.add_argument("--capture-pre-initdata-state", action="store_true",
                        help="capture safe GPU data/shared state after building "
                             "the descriptor, then exit before sending initdata")
    parser.add_argument("--capture-pre-secondary-initdata-state",
                        action="store_true",
                        help="wait for primary init acknowledgement, start the "
                             "secondary graphics endpoints, capture safe GPU "
                             "data/shared state, then exit before sending the "
                             "secondary initdata")
    args = parser.parse_args()
    if args.control_start_gap_ms < 0:
        parser.error("--control-start-gap-ms must be non-negative")
    if args.defer_full_control and not args.full_control:
        parser.error("--defer-full-control requires --full-control")
    if args.read_crash:
        globals()["READ_CRASH"] = True
    if args.capture_pre_secondary_initdata_state and args.instances < 2:
        parser.error("--capture-pre-secondary-initdata-state requires "
                     "--instances 2")
    if args.native_root_neighbors and not args.live_root_offset:
        parser.error("--native-root-neighbors requires --live-root-offset")
    if args.full_control and not args.context_queue_state:
        # The 0x20 entry registers the shared control object, which --context-queue-state builds.
        parser.error("--full-control needs --context-queue-state, which places the shared "
                     "control object the 0x20 entry registers")
    if args.descriptor_tails and not (args.render_context
                                      and args.context_queue_state):
        # The tails name render status pages and the shared control object, so both have to
        # exist before the redirect can point at them.
        parser.error("--descriptor-tails needs --render-context and "
                     "--context-queue-state")
    if args.publish_backend_group and args.prestage_backend_group:
        parser.error("--publish-backend-group and --prestage-backend-group "
                     "select mutually exclusive publication phases")
    if args.native_memory_layout:
        if args.native_main_dvas:
            parser.error("--native-memory-layout already places both main objects")
        if args.live_root_offset not in (0, g17p.NATIVE_ROOT_OFFSET):
            parser.error("--native-memory-layout requires the measured root offset")
        args.native_channel_state_layout = True
        args.native_object_attrs = True
        args.native_root_neighbors = True
        args.live_root_offset = g17p.NATIVE_ROOT_OFFSET
        args.state_after_control = True
    if args.secondary_root_extra == "auto":
        args.secondary_root_extra = (
            "both" if args.native_memory_layout else "none"
        )

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ARTIFACTS / ("coldboot_%s" % stamp)
    out.mkdir(parents=True, exist_ok=True)
    print("Cold boot attempt, artifacts at %s" % out)

    if args.seed_fixed_regions:
        # The device tree declares four carveouts for the accelerator, and this script
        # has only ever written one of them, the handoff. Firmware maps another of them
        # itself: its own fault report lists 0x101fff38000, the shared region, among
        # its code and data mappings. A capture of a running machine has 7106 non-zero
        # bytes in that region's 0x80000, and this host leaves all of it zero.
        #
        # That is also the difference between the two host paths in this project. The
        # replay path restores these carveouts and gets the device-control entry
        # consumed; this one never touches them and gets nothing consumed.
        #
        # Caveat worth keeping in view: the capture is taken after firmware has run, so
        # some of this content is firmware's own rather than the host's. Seeding all of
        # it is what the replay does, and the point here is to find out whether the
        # carveouts are the difference, not yet to establish who owns which byte.
        manifest_path = pathlib.Path(args.seed_fixed_regions) / "manifest.json"
        seeded = []
        with open(manifest_path) as handle:
            regions = json.load(handle)["fixed_regions"]
        skipped = []
        wanted = set(args.seed_fixed_region or SEEDABLE_FIXED_REGIONS)
        for region in regions:
            name = region["name"]
            if name not in wanted:
                # Measured, each on hardware: `gpu-region` is the translation root table this path
                # builds, so seeding a capture's puts the roots of tables this world does not have
                # in it; `gfx-data` and `gfx1-data` are the coprocessors' own data carveouts and
                # writing a captured copy over them stops them booting; `gfx-handoff` is written
                # explicitly later; and the two `:text` regions are protected, so a write faults on
                # the target. What is left, and what this path genuinely leaves zero, is the shared
                # pair.
                skipped.append((name, "not in the seedable set"))
                continue
            if name.endswith(":text"):
                # Not writable from here: these carveouts hold the coprocessors' own code and are
                # protected, so a write faults on the target and takes the proxy transfer with it.
                # They are also not this host's to provide: each coprocessor is loaded before this
                # script runs.
                skipped.append((name, "protected coprocessor code"))
                continue
            blob = (pathlib.Path(args.seed_fixed_regions)
                    / region["file"]).read_bytes()
            region_pa = int(region["pa"])
            try:
                iface.writemem(region_pa, blob)
            except Exception as exc:
                # Report rather than abort: which carveouts a host can write is itself the
                # question, and one unwritable region should not cost the whole run.
                skipped.append((name, str(exc).splitlines()[0]))
                continue
            p.dc_civac(region_pa, len(blob))
            seeded.append((name, region_pa, len(blob)))
            print("  seeded %-22s at %#x, %#x bytes" % (name, region_pa, len(blob)))
        for name, reason in skipped:
            print("  skipped %-21s %s" % (name, reason))

    smc_client = None
    if args.start_smc:
        # Every interval of host register activity during bring-up is traced and
        # empty, every object is byte-exact, and the doorbell and staged entry are
        # confirmed, yet the graphics instance declines to service its ring. That
        # points at something firmware expects to be present rather than at anything
        # the host does. The graphics firmware runs power-management tasks and the
        # second instance is a power instance whose faulting task is the power one;
        # power management on this platform is the management coprocessor's business,
        # and a bare-metal path never completes its handshake while a full operating
        # system always has. Reachable here: it answers with 2333 keys.
        from m1n1.fw.smc import SMCClient
        smc_client = SMCClient(u, int(u.adt["arm-io/smc"].get_reg(0)[0]))
        smc_client.verbose = 0
        smc_client.start()
        smc_client.start_ep(0x20)
        print("  management coprocessor up, %d keys"
              % smc_client.epmap[0x20].read32b("#KEY"))

    sgx = u.adt["/arm-io/sgx"]
    handoff_base = int(sgx.gfx_handoff_base)
    print("Powering the accelerator and its coprocessors")
    for path in ("/arm-io/gfx-asc", "/arm-io/gfx1-asc", "/arm-io/sgx"):
        p.pmgr_adt_power_enable(path)
    sgx_base = int(sgx.get_reg(0)[0])
    for offset in (0x1000104, 0x1000108):
        addr = sgx_base + offset
        p.write32(addr, int(p.read32(addr)) | 1)
    # The recorded values a working host leaves in these two after its
    # read-modify-write. If this host's writes land somewhere else, the accelerator
    # is configured differently before firmware ever starts.
    observed = [int(p.read32(sgx_base + off)) for off in (0x1000104, 0x1000108)]
    print("  applied the AXI transition workaround at %#x, registers now %s"
          % (sgx_base, " ".join("%#010x" % v for v in observed)))
    expected = (0x00010001, 0x000413b1)
    for got, want in zip(observed, expected):
        if got != want:
            print("    NOTE: %#010x differs from the recorded %#010x" % (got, want))
    if args.capture_pre_run_state:
        phase_dir = out / "direct_pre_first_run"
        manifest = save_phase_state(
            iface, p, u.adt, phase_dir, "direct-pre-first-asc-run",
            {"after_power_enable": True, "after_axi_transition": True},
        )
        print("Captured direct pre-RUN state -> %s" % manifest)
        return 0

    # The region above the coprocessor's private range is where firmware objects
    # are expected to live; this comes from the device tree, not from a capture.
    kern_va_base = (int(sgx.rtkit_private_vm_region_base)
                    + int(sgx.rtkit_private_vm_region_size))
    uat = UAT(iface, u)
    uat.allocator = Heap(kern_va_base + 0x80000000,
                         kern_va_base + 0x81000000, PAGE)

    # There are two firmware instances, not one, and the start sequence addresses
    # both. A host that brings up only the primary gets a descriptor acknowledged
    # and then nothing further: the device-control ring is never serviced.
    paths = list(g17p.COPROCESSOR_NODES[:args.instances])
    boot_paths = list(reversed(paths)) if args.start_secondary_first else paths
    asc_by_path = {}
    asc_type = NativeColdASC if args.native_sequence else ColdASC
    for path in boot_paths:
        instance = asc_type(u, int(u.adt[path].get_reg(0)[0]),
                            dart=uat, stream=args.context)
        instance.verbose = args.verbose_asc
        instance.mgmt.verbose = args.verbose_asc
        asc_by_path[path] = instance

    def start_coprocessor(path):
        instance = asc_by_path[path]
        # What state is the coprocessor in before this host starts it? If something
        # earlier in the boot chain already started firmware, then the run bit is a
        # no-op, firmware is past its own initialisation, and a start notification
        # it has already handled would reasonably be declined.
        pre_control = int(p.read32(int(u.adt[path].get_reg(0)[0]) + 0x0044))
        pre_status = int(p.read32(int(u.adt[path].get_reg(0)[0]) + 0x0048))
        print("  %s before start: CPU_CONTROL=%#x (run=%d) CPU_STATUS=%#x "
              "(running=%d stopped=%d idle=%d)"
              % (path, pre_control, (pre_control >> 4) & 1, pre_status,
                 pre_status & 1, (pre_status >> 1) & 1, (pre_status >> 5) & 1))
        instance.boot()
        if args.iop_power:
            instance.start()
        else:
            # A working host never asks the coprocessor to change its own power
            # state here. Captured from a live mailbox dialogue: it acknowledges the
            # greeting, starts the crash endpoint, acknowledges the endpoint map,
            # sets the host power state, then starts the two graphics endpoints. The
            # generic path inserts a coprocessor power-state request that is absent
            # there, and by this point the state it would ask for has already been
            # reached on its own.
            instance.mgmt.wait_boot(3)
        if not args.native_sequence:
            instance.start_ep(0x20)
            instance.start_ep(0x21)
        print("  %s running%s"
              % (path, "" if args.native_sequence else ", endpoints up"))

    if args.build_before_run:
        print("Deferring coprocessor RUN until UAT and initdata are built")
    else:
        print("Starting the coprocessors")
        for path in boot_paths:
            start_coprocessor(path)
    # Roots and their control messages are assigned primary then secondary. Keep
    # that logical order separate from the order in which their ASC cores ran.
    ascs = [asc_by_path[path] for path in paths]
    asc = ascs[0]

    # The standard UAT initializer normally clears this page. In the baseline path,
    # sample it after ASC startup to expose anything firmware published. In
    # --build-before-run mode, this intentionally samples and initializes the page
    # before firmware can observe or change it.
    shared_root_before = bytes(iface.readmem(uat.ttbr1_base, PAGE))
    shared_root_nonzero_before = [
        index for index, value in enumerate(struct.unpack("<2048Q", shared_root_before))
        if value
    ]
    print("  shared upper root at %#x has %d non-zero entries before host UAT setup%s"
          % (uat.ttbr1_base, len(shared_root_nonzero_before),
             " (preserving)" if args.preserve_shared_root else ""))
    context_pairs_before = [
        [int(p.read64(uat.gpu_region + context * 16)),
         int(p.read64(uat.gpu_region + context * 16 + 8))]
        for context in range(uat.NUM_CONTEXTS)
    ]
    active_contexts_before = [
        context for context, pair in enumerate(context_pairs_before) if any(pair)
    ]
    print("  hardware UAT contexts populated before host setup: %s"
          % (active_contexts_before if active_contexts_before else "none"))

    # The upper half of the address space is rooted in a table that lives in the
    # accelerator's reserved memory. Check whether that table is writable at all
    # before trusting anything built in it: a dropped write leaves the in-memory
    # shadow looking correct while the coprocessor sees nothing.
    firmware_root = uat.ttbr1_base
    probe_slot = firmware_root + 0x10
    saved = int(p.read64(probe_slot))
    p.write64(probe_slot, 0xdeadbeef00000000)
    writable = int(p.read64(probe_slot)) == 0xdeadbeef00000000
    p.write64(probe_slot, saved)
    print("  upper root at %#x is %s"
          % (firmware_root, "writable" if writable else "write protected"))

    if args.private_upper_root:
        # Give ourselves a table we can actually write, carrying over the entries the
        # firmware made for its own code and data so it keeps running, and leaving the
        # rest free for this script's mappings.
        private_root = u.memalign(PAGE, PAGE)
        p.memset32(private_root, 0, PAGE)
        inherited = 0
        for i in range(uat.LEVELS[1][1]):
            entry = int(p.read64(firmware_root + 8 * i))
            if entry:
                p.write64(private_root + 8 * i, entry)
                inherited += 1
        p.dc_civac(private_root, PAGE)
        # Two different write paths reach this memory: single-word stores issued by
        # the target, and bulk transfers. They do not necessarily agree, and a table
        # written through a path that does not stick looks fine in the shadow copy
        # while the coprocessor sees an empty table, so check both here.
        import struct as _struct
        word_ok = int(p.read64(private_root)) == int(p.read64(firmware_root))
        bulk = iface.readmem(private_root, 64 * 8)
        bulk_nonzero = sum(1 for v in _struct.unpack("<64Q", bulk) if v)
        print("  private root: word path %s, bulk path sees %d non-zero entries"
              % ("agrees" if word_ok else "DISAGREES", bulk_nonzero))
        uat.ttbr1_base = private_root
        print("  using a private upper root at %#x, inheriting %d firmware entries"
              % (private_root, inherited))
    else:
        private_root = firmware_root

    handoff_words = [int(p.read64(handoff_base + off)) for off in (0x0, 0x8, 0x10)]
    print("  handoff at %#x reads %s"
          % (handoff_base, " ".join("%#018x" % w for w in handoff_words)))
    if not args.handoff:
        uat.handoff = AbsentHandoff()
    if args.preserve_shared_root:
        initialize_uat_preserving_shared_root(uat)
    print("Building an address space of our own from va %#018x" % kern_va_base)
    uat.bind_context(args.context, uat.ttbr0_base)
    if args.mirror_context_zero:
        # Native XNU has context 0 populated by the initdata handoff. The normal
        # direct path leaves it empty because bind_context intentionally rejects
        # that special host context. This is an explicit experiment, not a change
        # to the baseline mapping policy.
        uat.set_l0(0, 0, uat.ttbr0_base)
        uat.set_l0(0, 1, uat.ttbr1_base)
    if args.bind_all:
        # Which translation context each firmware instance walks with is not
        # established. Binding every non-zero context to the same tables removes
        # that question for contexts 1 through 63. Context 0 is controlled only by
        # --mirror-context-zero so its native use can be tested independently.
        for ctx in range(1, uat.NUM_CONTEXTS):
            if ctx == args.context:
                continue
            uat.set_l0(ctx, 0, uat.ttbr0_base, ctx)
            uat.set_l0(ctx, 1, uat.ttbr1_base, ctx)
        uat.flush_dirty()
        uat.invalidate_cache()
    if args.native_context_slots:
        # A working host's root table separates the two contexts by slot: slot 1 carries the
        # firmware context tagged 64, and slot 7 carries the render context tagged 1. The slot is
        # the table position and the tag is the ASID field of each root pointer. This path binds
        # every slot with its own number as the tag, so the tag a work item names, 1, resolves to
        # slot 1, which is the slot firmware itself runs in. Reproduce the separation.
        # A working host does not give the firmware context a low-address root at all: its slot
        # reads root0 = 0, uniquely among the twelve. So firmware cannot reach the low alias region
        # through its own context and must reach the operand table through the render context, which
        # this path has never required of it because every context here carries both halves.
        uat.set_l0(NATIVE_FIRMWARE_SLOT, 1, uat.ttbr1_base, NATIVE_FIRMWARE_CONTEXT)
        uat.set_l0(NATIVE_RENDER_SLOT, 0, uat.ttbr0_base, NATIVE_RENDER_CONTEXT)
        if args.native_context_split:
            # Deferred. Every mapping this path makes goes through args.context, and both slots
            # point at the same two table hierarchies, so the mappings have to be created while
            # both roots are still reachable and the split applied once building is done. Zeroing
            # here made 98 render mappings stop resolving, which the translation check caught.
            print("  the context split will be applied after all mapping is done")
            uat.set_l0(NATIVE_FIRMWARE_SLOT, 0, uat.ttbr0_base,
                       NATIVE_FIRMWARE_CONTEXT)
            uat.set_l0(NATIVE_RENDER_SLOT, 1, uat.ttbr1_base,
                       NATIVE_RENDER_CONTEXT)
        else:
            uat.set_l0(NATIVE_FIRMWARE_SLOT, 0, uat.ttbr0_base,
                       NATIVE_FIRMWARE_CONTEXT)
            uat.set_l0(NATIVE_RENDER_SLOT, 1, uat.ttbr1_base,
                       NATIVE_RENDER_CONTEXT)
        uat.flush_dirty()
        uat.invalidate_cache()
        print("  slot %d tagged %d for firmware, slot %d tagged %d for the render context"
              % (NATIVE_FIRMWARE_SLOT, NATIVE_FIRMWARE_CONTEXT,
                 NATIVE_RENDER_SLOT, NATIVE_RENDER_CONTEXT))

    bound_description = "contexts 1-63" if args.bind_all else "context %d" % args.context
    if args.mirror_context_zero:
        bound_description += " plus context 0"
    print("  bound %s to a fresh table at %#x" % (bound_description, uat.ttbr0_base))

    arena = Arena(
        uat, args.context,
        kern_va_base + (g17p.NATIVE_HWDATA_OFFSET
                        if args.native_memory_layout else args.hwdata_offset))
    private_cluster_va = private_cluster_pa = None
    if args.native_memory_layout:
        private_cluster_va, private_cluster_pa = arena.alloc_at(
            kern_va_base + g17p.NATIVE_PRIVATE_CLUSTER_OFFSET,
            g17p.NATIVE_PRIVATE_CLUSTER_SIZE, "native_private_state")

    print("Allocating and building the descriptor objects")
    # The allocation reaches past the bundle itself, because the main object's
    # repeated address names the bundle plus 0xc500, which is outside 0xc000.
    hwdata_va, hwdata_pa = arena.alloc(
        g17p.NATIVE_SHARED_CLUSTER_SIZE if args.native_memory_layout
        else g17p.HWDATA_BUNDLE_ALLOC_SIZE,
        "hwdata_bundle")
    repeated_va = hwdata_va + g17p.MAIN_REPEATED_ADDR_OFFSET

    # Firmware reaches its own registers through the table in the hardware-data
    # object, not through any fixed address, so the windows have to be both mapped
    # into the address space and declared in the table. Two windows are not granule
    # aligned; they share an offset within their page, so mapping the containing
    # page places them correctly.
    register_entries = {}
    for slot, phys, device_va, size, unk_18, flag in g17p.REGISTER_WINDOWS:
        page_phys = phys & ~(PAGE - 1)
        page_va = device_va & ~(PAGE - 1)
        span = (((device_va + size) - page_va) + PAGE - 1) & ~(PAGE - 1)
        uat.iomap_at(args.context, page_va, page_phys, span,
                     AttrIndex=MemoryAttr.Device, AP=1)
        register_entries[slot] = {"phys": phys, "device_va": device_va,
                                  "size": size, "flag": flag, "unk_18": unk_18}
    uat.flush_dirty()
    print("  mapped %d register windows, %d further slots declared empty"
          % (len(register_entries), len(g17p.REGISTER_FLAG_ONLY_SLOTS)))

    # The hardware-data object also names two regions of its own. Leaving them empty
    # is the last difference from what a working host hands the firmware.
    region_records = []
    for index, record in enumerate(g17p.HWDATA_REGION_RECORDS):
        if args.native_memory_layout:
            addr, _ = arena.alloc_at(
                hwdata_va + g17p.NATIVE_HWDATA_REGION_OFFSETS[index],
                PAGE, "hwdata_region_%d" % index)
        else:
            addr, _ = arena.alloc(PAGE, "hwdata_region_%d" % index)
        region_records.append(dict(record, addr=addr))
    if args.native_memory_layout:
        bundle_state_va = kern_va_base + g17p.NATIVE_HWDATA_STATE_OFFSET
    else:
        bundle_state_va, _ = arena.alloc(PAGE, "hwdata_state")

    arena.write(hwdata_pa, build.build_hwdata(register_entries,
                                              g17p.REGISTER_FLAG_ONLY_SLOTS,
                                              (blank_perf_tables()
                                               if args.blank_perf
                                               else g17p.PERF_TABLES),
                                              chip_id=g17p.CHIP_ID,
                                              region_records=region_records))
    if args.no_state_ptr:
        # Leave the state pointer clear and let firmware fill it in. A live capture
        # of a running firmware holds 0xfffffc2000197480 there, which is not in the
        # region host objects are allocated from: native's own root sits at
        # 0xfffffc2010030000, alongside everything this host builds, while that
        # address is far below it, in the coprocessor's private range. A pointer
        # firmware writes into its own private memory is not one a host supplies,
        # and nothing has ever checked this offset, because the regression gate
        # only verifies the bundle's internal view relations.
        print("  leaving the bundle state pointer clear for firmware to fill")
    elif not args.state_after_control:
        arena.write(hwdata_pa + g17p.HWDATA_BUNDLE_STATE_PTR,
                    struct.pack("<Q", bundle_state_va))
    for offset, data in g17p.HWDATA_BUNDLE_STATIC_RUNS:
        arena.write(hwdata_pa + offset, data)
    if args.bundle_word_b75c is not None:
        arena.write(hwdata_pa + 0xb75c,
                    struct.pack("<I", args.bundle_word_b75c))
    # The primary main object's five bare addresses are views into this same
    # allocation, not separately allocated objects. Overlay each view's known
    # populated runs while preserving the hardware-data bytes beneath addr0/1
    # and the extensive overlap between addr3/4.
    for view_offset, valid_size, spec in zip(
            g17p.MAIN_ADDR_OBJECT_OFFSETS,
            g17p.MAIN_ADDR_OBJECT_VALID_SIZES,
            g17p.MAIN_ADDR_OBJECTS):
        for offset, data in spec["runs"]:
            # Older captures read physically past the end of unaligned views.
            # Only bytes inside the view's actual virtual-page extent are valid.
            if offset + len(data) > valid_size:
                continue
            arena.write(hwdata_pa + view_offset + offset, data)
    # Read back the pointers firmware is known to dereference. A null here is
    # indistinguishable, from the fault alone, from a populated object whose
    # contents are wrong, and the two call for opposite fixes.
    for label, offset in (("bundle state pointer", g17p.HWDATA_BUNDLE_STATE_PTR),):
        value = struct.unpack("<Q", bytes(iface.readmem(hwdata_pa + offset, 8)))[0]
        print("  %s at bundle+%#x reads %#x%s"
              % (label, offset, value, "" if value else "  <-- NULL"))

    # The two roots have to sit a fixed distance apart: the secondary's
    # initialisation message is the primary's address plus that distance in the same
    # field, so their placement is not free.
    # The roots are placed on the delta itself, not merely that far apart. Every
    # observed pair is aligned to it, and an unaligned primary leaves the secondary
    # unable to translate its own root.
    if args.live_root_offset:
        # Place the roots where a working host places them. Nothing observable
        # depends on the address, but the second instance's fault has survived every
        # content change, and its address is the one input never varied.
        arena.va = kern_va_base + args.live_root_offset
    root_pages = None
    if args.native_memory_layout:
        roots_va = kern_va_base + g17p.NATIVE_ROOT_OFFSET
        root_pages = [
            arena.alloc_at(roots_va + slot * g17p.SECONDARY_ROOT_DELTA,
                           PAGE, "root%d" % slot)
            for slot in range(len(ascs))
        ]
        roots_pa = root_pages[0][1]
        span = PAGE
        arena.va = roots_va + 3 * g17p.SECONDARY_ROOT_DELTA
    else:
        span = g17p.SECONDARY_ROOT_DELTA * (len(ascs) + 1)
        raw_va, raw_pa = arena.alloc(span, "roots")
        skew = (-raw_va) % g17p.SECONDARY_ROOT_DELTA
        roots_va = raw_va + skew
        roots_pa = raw_pa + skew

    # Both instances are handed the same data region and the same leading region.
    # Giving the second instance private copies is a difference from what a working
    # host does, and these are shared rather than duplicated for that reason.
    if args.native_memory_layout:
        region_c_va, region_c_pa = arena.alloc_at(
            roots_va - g17p.SECONDARY_ROOT_DELTA,
            build.REGION_C_SIZE, "region_c")
        region_a_va, region_a_pa = arena.alloc_at(
            roots_va + 2 * g17p.SECONDARY_ROOT_DELTA,
            PAGE, "region_a")
    elif args.native_root_neighbors:
        region_c_va, region_c_pa = arena.alloc_at(
            roots_va - g17p.SECONDARY_ROOT_DELTA,
            build.REGION_C_SIZE, "region_c")
        region_a_va = roots_va + 2 * g17p.SECONDARY_ROOT_DELTA
        region_a_pa = roots_pa + 2 * g17p.SECONDARY_ROOT_DELTA
        print("  %-16s va %#018x  pa %#014x  %#x bytes (inside roots)"
              % ("region_a", region_a_va, region_a_pa, PAGE))
    else:
        region_a_va, region_a_pa = arena.alloc(PAGE, "region_a")
        region_c_va, region_c_pa = arena.alloc(build.REGION_C_SIZE, "region_c")
    arena.write(region_c_pa, build.build_region_c())

    instances = []
    primary_addr_array = None
    native_main_offsets = (0xc07a65c0, 0xc07aaa80)
    for slot, name in enumerate(g17p.COPROCESSOR_NAMES[:len(ascs)]):
        if args.native_memory_layout:
            offset = (g17p.NATIVE_PRIMARY_MAIN_OFFSET if slot == 0
                      else g17p.NATIVE_SECONDARY_MAIN_OFFSET)
            main_va, main_pa = hwdata_va + offset, hwdata_pa + offset
            print("  %-16s va %#018x  pa %#014x  %#x bytes (shared cluster)"
                  % ("%s_main" % name, main_va, main_pa, build.MAIN_SIZE))
        elif args.native_main_dvas:
            main_va, main_pa = arena.alloc_at(
                kern_va_base + native_main_offsets[slot],
                build.MAIN_SIZE, "%s_main" % name)
        else:
            main_va, main_pa = arena.alloc(build.MAIN_SIZE, "%s_main" % name)
        if args.native_memory_layout:
            if slot == 0:
                state_va = kern_va_base + g17p.NATIVE_PRIMARY_WORK_STATE_OFFSET
                status_a_va = kern_va_base + g17p.NATIVE_PRIMARY_STATUS_A_OFFSET
                status_b_va = state_va + g17p.NATIVE_STATUS_B_OFFSET
            else:
                state_va = kern_va_base + g17p.NATIVE_SECONDARY_WORK_STATE_OFFSET
                status_a_va = kern_va_base + g17p.NATIVE_SECONDARY_STATUS_A_OFFSET
                status_b_va = 0
            state_pa = private_cluster_pa + (state_va - private_cluster_va)
            status_a_pa = private_cluster_pa + (
                status_a_va - private_cluster_va)
            status_b_pa = (private_cluster_pa
                           + status_b_va - private_cluster_va
                           if status_b_va else None)
            tail_va, tail_pa = status_a_va, status_a_pa
        elif args.native_channel_state_layout:
            state_va, state_pa = arena.alloc(PAGE, "%s_work_state" % name)
            tail_va, tail_pa = arena.alloc(
                g17p.NATIVE_TRAILING_STATE_SIZE, "%s_trailing_state" % name)
            status_a_va, status_a_pa = tail_va, tail_pa
            if slot == 0:
                status_b_va = state_va + g17p.NATIVE_STATUS_B_OFFSET
                status_b_pa = state_pa + g17p.NATIVE_STATUS_B_OFFSET
            else:
                status_b_va, status_b_pa = 0, None
        else:
            status_a_va, status_a_pa = arena.alloc(PAGE, "%s_status_a" % name)
            # Only the first instance is given a second status block; the second
            # instance's root carries zero there.
            if slot == 0:
                status_b_va, status_b_pa = arena.alloc(
                    PAGE, "%s_status_b" % name)
            else:
                status_b_va, status_b_pa = 0, None
            state_va, state_pa = arena.alloc(
                g17p.CHANNEL_STATE_STRIDE * build.CHANNEL_TABLE_ENTRIES,
                "%s_channel_state" % name)
        # Work rings are 0x18-byte slots on the confirmed 0x1800 stride. The
        # non-work rings carry 0x40-byte entries and their indices are validated
        # below 0x100, so 256 entries needs 0x4000 each. Giving every channel the
        # work stride leaves the control ring a quarter of the size firmware may
        # index into, and overlapping the ring after it.
        work_span = g17p.RING_STRIDE * g17p.CHANNEL_TABLE_WORK_COUNT
        if args.native_memory_layout:
            ring_va = hwdata_va + min(g17p.NATIVE_WORK_RING_OFFSETS)
            ring_pa = hwdata_pa + min(g17p.NATIVE_WORK_RING_OFFSETS)
        else:
            other = build.CHANNEL_TABLE_ENTRIES - g17p.CHANNEL_TABLE_WORK_COUNT
            ring_va, ring_pa = arena.alloc(
                work_span + other * g17p.SERVICE_RING_SIZE,
                "%s_channel_rings" % name)

        def ring_for(index):
            if args.native_memory_layout:
                if index < g17p.CHANNEL_TABLE_WORK_COUNT:
                    return hwdata_va + g17p.NATIVE_WORK_RING_OFFSETS[index]
                if index == g17p.CHANNEL_TABLE_WORK_COUNT:
                    return main_va + build.MAIN_INTERVAL
                offset = g17p.NATIVE_TRAILING_RING_OFFSETS.get(index)
                return status_a_va + offset if offset is not None else 0
            if index < g17p.CHANNEL_TABLE_WORK_COUNT:
                return ring_va + index * g17p.RING_STRIDE
            return (ring_va + work_span
                    + (index - g17p.CHANNEL_TABLE_WORK_COUNT)
                    * g17p.SERVICE_RING_SIZE)

        # The last two entries are not fully populated in a capture: one carries a
        # first state address and no ring, the other is entirely empty. Filling them
        # like the rest declares two channels that do not exist, so match what the
        # hardware is actually given.
        channels = []
        channel_state_pas = []
        for index in range(build.CHANNEL_TABLE_ENTRIES):
            if args.native_channel_state_layout and index <= 12:
                offset = g17p.NATIVE_WORK_STATE_OFFSETS[index]
                states = [state_va + offset
                          + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                          for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
                state_pas = [state_pa + offset
                             + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                             for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
            elif (args.native_channel_state_layout
                  and index in g17p.NATIVE_TRAILING_STATE_OFFSETS):
                offsets = g17p.NATIVE_TRAILING_STATE_OFFSETS[index]
                states = [tail_va + offset if offset is not None else 0
                          for offset in offsets]
                if args.native_memory_layout:
                    state_pas = [
                        private_cluster_pa + (address - private_cluster_va)
                        if address else 0 for address in states
                    ]
                else:
                    state_pas = [tail_pa + offset if offset is not None else 0
                                 for offset in offsets]
            elif args.native_channel_state_layout:
                states = [0, 0, 0]
                state_pas = [0, 0, 0]
            else:
                block = state_va + index * g17p.CHANNEL_STATE_STRIDE
                states = [block + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                          for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
                state_pas = [state_pa + index * g17p.CHANNEL_STATE_STRIDE
                             + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                             for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
            ring = ring_for(index)
            if index == g17p.CHANNEL_TABLE_WORK_COUNT:
                # Device control is embedded in the main object. On both native
                # instances its ring pointer is exactly main + 0x4c0, where the
                # builder places the initial 0x16/0x2a opcode.
                ring = main_va + build.MAIN_INTERVAL
            if index == g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [states[0], 0, 0], 0
                state_pas = [state_pas[0], 0, 0]
            elif index > g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [0, 0, 0], 0
                state_pas = [0, 0, 0]
            channels.append((states, ring))
            channel_state_pas.append(state_pas)

        if slot == 0:
            # The main configuration object carries five bare addresses and three
            # region triples. Firmware follows them without checking, so a
            # placeholder zero is a fault at a small offset from zero.
            # These five are not scratch or independent allocations. They are
            # fixed internal views of the hardware-data bundle populated above.
            addr_array = [
                hwdata_va + offset
                for offset in g17p.MAIN_ADDR_OBJECT_OFFSETS
            ]
            primary_addr_array = list(addr_array)
            if args.native_memory_layout:
                # This selected-root page is reached through a computed scheduler
                # address after the initial endpoint-0x23 peer exchange. It has no
                # raw descriptor pointer for a closure walker to discover.
                arena.alloc_at(
                    kern_va_base + g17p.NATIVE_PRIMARY_COMPUTED_PAGE_OFFSET,
                    PAGE, "%s_computed_page" % name)
                region_triples = []
                for index, (offset, value) in enumerate(
                        g17p.NATIVE_PRIMARY_REGION_TRIPLES):
                    addr = kern_va_base + offset
                    # The first address is intentionally unresolved in the native
                    # firmware context. The other two name blank shared pages.
                    if index:
                        arena.alloc_at(addr, PAGE,
                                       "%s_region_%d" % (name, index))
                    region_triples.append((addr, value))
            else:
                region_triples = [
                    (arena.alloc(PAGE, "%s_region_%d" % (name, i))[0], 0)
                    for i in range(build.MAIN_REGION_TRIPLE_COUNT)
                ]
            arena.write(main_pa, build.build_main_config(
                hwdata_va, repeated_va, channels, addr_array, region_triples))
        else:
            # The second instance is handed a control-only object: no work channels,
            # no address array, and region triples carrying values but no addresses.
            # It shares the first instance's hardware-data object. Handing it a copy
            # of the first instance's object instead is what made it fault.
            addr_array = []
            region_triples = list(g17p.SECONDARY_REGION_TRIPLES)
            extra_addr = (
                primary_addr_array[g17p.SECONDARY_EXTRA_ADDR_OBJECT]
                + g17p.SECONDARY_EXTRA_ADDR_OFFSET
            )
            arena.write(main_pa, build.build_secondary_main_config(
                hwdata_va, repeated_va, channels, region_triples, extra_addr))
        arena.write(
            status_a_pa,
            build.build_status_block(
                extra=(slot == 0 and not args.no_primary_status_extra)
            ),
        )
        if status_b_pa is not None:
            arena.write(status_b_pa, build.build_status_block())

        root_va = roots_va + slot * g17p.SECONDARY_ROOT_DELTA
        root_pa = (root_pages[slot][1] if root_pages is not None
                   else roots_pa + slot * g17p.SECONDARY_ROOT_DELTA)
        secondary_extra_0 = 0
        secondary_extra_1 = 0
        if slot == 1 and args.secondary_root_extra in ("first", "both"):
            secondary_extra_0 = (
                args.secondary_root_extra_first_dva
                if args.secondary_root_extra_first_dva is not None else
                kern_va_base + g17p.NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS[0]
            )
        if slot == 1 and args.secondary_root_extra in ("second", "both"):
            secondary_extra_1 = (
                kern_va_base + g17p.NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS[1])
        arena.write(root_pa, build.build_root(
            version=[0x04c0, 0x0396, 0xa322, 0x0c8a],
            # Every capture has this address zero. Supplying a real region makes
            # firmware follow it into a structure this script has not filled in.
            region_a=region_a_va, main_config=main_va, region_c=region_c_va,
            status_a=status_a_va, status_b=status_b_va, kind=slot,
            secondary_extra_0=secondary_extra_0,
            secondary_extra_1=secondary_extra_1))
        instances.append({"name": name, "ring_va": ring_va,
                          "root_va": root_va, "root_pa": root_pa,
                          "state_pa": state_pa, "state_va": state_va,
                          "channels": channels,
                          "channel_state_pas": channel_state_pas,
                          "ring_pa": ring_pa,
                          "main_va": main_va,
                          "control_ring_pa": main_pa + build.MAIN_INTERVAL,
                          "status_a_pa": status_a_pa, "status_b_pa": status_b_pa,
                          "region_c_pa": region_c_pa, "main_pa": main_pa})
        print("  %s root at va %#018x" % (name, root_va))

    if args.native_object_attrs:
        # Native immutable firmware inputs are ordinary WB memory. Objects the
        # host and firmware mutate are mapped Shared, and the root-side objects
        # are the only data pages not marked UXN.
        uat.iomap_at(args.context, hwdata_va, hwdata_pa,
                     (g17p.NATIVE_SHARED_CLUSTER_SIZE
                      if args.native_memory_layout
                      else g17p.HWDATA_BUNDLE_SIZE),
                     AttrIndex=MemoryAttr.Normal, AP=1)
        for record in region_records:
            addr = record["addr"]
            region = next(entry for entry in arena.entries
                          if entry["va"] == addr)
            uat.iomap_at(args.context, region["va"], region["pa"], PAGE,
                         AttrIndex=MemoryAttr.Normal, AP=1)
        if args.native_memory_layout:
            for root_va, root_page_pa in root_pages:
                uat.iomap_at(args.context, root_va, root_page_pa, PAGE,
                             AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
            uat.iomap_at(args.context, region_a_va, region_a_pa, PAGE,
                         AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
        else:
            uat.iomap_at(args.context, roots_va, roots_pa, span,
                         AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
        uat.iomap_at(args.context, region_c_va,
                     region_c_pa & ~(PAGE - 1), PAGE,
                     AttrIndex=MemoryAttr.Shared, AP=1, UXN=0)
        # The main configuration object and the work-channel rings are AttrIndex 0 in a working
        # host's tables, fully cached inner and outer, and this remap was skipped whenever
        # --native-memory-layout was in force, which is every run this path has made for weeks.
        # They kept the arena's Shared, inner non-cacheable, which is the wrong cacheability on
        # exactly the two structures firmware walks to find and service work. The capture's own
        # leaves: the two rings and the main object AttrIndex 0, while the root, the data region,
        # the channel state block and the private cluster pages are AttrIndex 2.
        for entry in instances:
            uat.iomap_at(args.context, entry["main_va"] & ~(PAGE - 1),
                         entry["main_pa"] & ~(PAGE - 1), PAGE,
                         AttrIndex=MemoryAttr.Normal, AP=1)
            # Under the native layout the rings start part-way into a page, as the capture's do at
            # `+0xdc0`, so the remap has to be taken from the containing page rather than the ring
            # address itself.
            ring_base_va = entry["ring_va"] & ~(PAGE - 1)
            ring_base_pa = entry["ring_pa"] & ~(PAGE - 1)
            work_span = ((entry["ring_va"] - ring_base_va)
                         + g17p.RING_STRIDE * g17p.CHANNEL_TABLE_WORK_COUNT)
            work_span = (work_span + PAGE - 1) & ~(PAGE - 1)
            uat.iomap_at(args.context, ring_base_va, ring_base_pa,
                         work_span, AttrIndex=MemoryAttr.Normal, AP=1)
        uat.flush_dirty()
        uat.invalidate_cache()
        print("  applied native UAT object memory attributes, including the main "
              "object and the work rings as Normal")

    if args.state_after_control:
        # Put the state object where a native capture puts it: a fixed distance
        # above the second instance's device-control state block. A standalone page
        # satisfies the pointer but not the relation, and firmware faults inside the
        # path that selects this object.
        secondary_instance = instances[-1]
        control_state = secondary_instance["channels"][
            g17p.CHANNEL_TABLE_WORK_COUNT][0][0]
        placed = control_state + g17p.HWDATA_STATE_AFTER_CONTROL_STATE
        arena.write(hwdata_pa + g17p.HWDATA_BUNDLE_STATE_PTR,
                    struct.pack("<Q", placed))
        print("  state object placed at %#x, the secondary control state %#x "
              "plus %#x" % (placed, control_state,
                            g17p.HWDATA_STATE_AFTER_CONTROL_STATE))

    uat.flush_dirty()

    secondary_root = None
    if len(ascs) > 1:
        # The second instance walks its own copy of the top table, in its own half of
        # the shared region. Entries the host made in the primary's table have to be
        # mirrored there or the secondary translates nothing it is handed. Its own
        # first entries describe its code and are left alone.
        secondary_root = uat.ttbr1_base + g17p.SECONDARY_SHARED_DELTA
        mirrored = 0
        for index in range(uat.LEVELS[1][1]):
            entry = int(p.read64(uat.ttbr1_base + 8 * index))
            existing = int(p.read64(secondary_root + 8 * index))
            if not entry or index < g17p.SHARED_FIRMWARE_ENTRIES:
                # The instance's own code and data live in the first entries. Those
                # differ per instance and must be left alone.
                continue
            if existing != entry:
                print("    entry %d: %#018x -> %#018x" % (index, existing, entry))
                p.write64(secondary_root + 8 * index, entry)
                mirrored += 1
        p.dc_civac(secondary_root, PAGE)
        print("  mirrored %d top-table entries into the secondary's table at %#x"
              % (mirrored, secondary_root))

    uat.invalidate_cache()
    root_va = instances[0]["root_va"]
    root_pa = instances[0]["root_pa"]
    state_pa = instances[0]["state_pa"]
    ring_pa = instances[0]["ring_pa"]
    status_a_pa = instances[0]["status_a_pa"]
    status_b_pa = instances[0]["status_b_pa"]
    region_c_pa = instances[0]["region_c_pa"]
    main_pa = instances[0]["main_pa"]

    # The upper-half root table is shared with the firmware, so its entries show
    # both the firmware's own mappings and the ones this script just made. If the
    # firmware faults on the descriptor, the question is whether the entry covering
    # it is present here at all, or present and not visible to the coprocessor.
    upper_root = uat.ttbr1_base
    import struct as _struct
    entries = list(_struct.unpack("<64Q", iface.readmem(upper_root, 64 * 8)))
    # Ask the translation-table code to resolve the descriptor through the same
    # tables it just wrote. If it resolves here but the coprocessor faults, the
    # tables are right and the coprocessor is looking somewhere else; if it fails
    # here too, the mapping never landed where the walk expects it.
    try:
        resolved = uat.iotranslate(args.context, root_va, 8)
    except Exception as exc:
        resolved = "failed: %s" % exc
    print("  host walk resolves the descriptor to %s" % (resolved,))
    selector_table = uat.gpu_region + args.context * 16
    selectors = [int(p.read64(selector_table + 8 * i)) for i in range(2)]
    print("  context %d selectors: lower %#018x  upper %#018x"
          % (args.context, selectors[0], selectors[1]))
    print("  context 0 selectors: lower %#018x  upper %#018x"
          % (int(p.read64(uat.gpu_region)), int(p.read64(uat.gpu_region + 8))))
    print("  upper root table at %#x" % upper_root)
    for i, entry in enumerate(entries):
        if entry:
            print("    [%d] %#018x  (word path %#018x)"
                  % (i, entry, int(p.read64(upper_root + 8 * i))))
    # Walk the descriptor address the way the hardware does, printing the table and
    # entry at every level. This says which tables the chain actually lives in, which
    # is the only way to tell a mapping that was never made from one that was made
    # somewhere the coprocessor does not look.
    print("  walk of %#018x:" % root_va)
    walk_table = uat.gpu_region + args.context * 16
    for level, (shift, count, cls) in enumerate(uat.LEVELS):
        index = (root_va >> shift) & (count - 1)
        entry = int(_struct.unpack("<Q", iface.readmem(walk_table + 8 * index, 8))[0])
        pte = cls(entry)
        print("    level %d: table %#014x index %4d entry %#018x valid=%s"
              % (level, walk_table, index, entry, bool(pte.valid())))
        if not pte.valid():
            break
        walk_table = pte.offset()

    level1_index = (root_va >> 36) & 0x3f
    print("  descriptor needs upper-root entry [%d], which reads %#018x"
          % (level1_index, entries[level1_index]))

    # A working host has the first device-control message already in the ring, with
    # the producer at one, before it hands over the descriptor. Staging afterwards
    # is what this script did, and firmware then never scans the channel: the ring
    # is read as part of accepting the descriptor, not in response to the later
    # notification.
    stage_count = (args.stage_control_instances
                   if args.stage_control_instances else len(instances))
    def build_full_control(entry):
        """The four entries a host publishes, with the 0x20 entry's objects built here.

        Field values are those a working host sends, read from the device-control ring of a
        snapshot. The only one rebuilt is the configuration object's address, since a from-cold
        world places that object wherever it likes.
        """
        # The object this entry registers is the shared control object, the same one every
        # first-work optional item names at its `+0x36`. This built a second copy of it at an
        # address of its own, so firmware registered that copy and the work referenced the other,
        # and no registration the work could use ever happened. Name the one object.
        # The address is a constant, so this does not depend on which of the two builders runs
        # first; --context-queue-state is what places the object there, and the parser requires it.
        config_va = SHARED_CONTROL_ADDRESS

        # The entry's `+0x1c` names the operand table and its `+0x24` the slot in it. Measured on
        # the capture: that page is **entirely zero** before the first `0x20`, and a mid-stream host
        # has nine entries in it, so the slot is firmware's to fill and not the host's. This wrote
        # the slot itself, which presents firmware with an operation whose output is already there.
        low_va = 0x0000007000208000
        operand_va = 0x00000070013a8000
        if not args.full_render_extent:
            # With the render context's full extent mapped, the operand buffers are already in
            # place on their own stride; without it, this is the only thing that maps this one.
            arena.alloc_at(operand_va, 0x100000, "control-operand-buffer",
                           flags=LOW_ALIAS_FLAGS)
        table_page = None
        if args.prefill_operand_entry:
            # The capture's operand table is empty before the first `0x20`, which is why this path
            # stopped writing the entry. But with the channel producers set so firmware services the
            # work as well as the opening, it takes a **write** fault to a null pointer inside the
            # `0x20` handler, and an empty slot is the obvious null. So the emptiness is testable
            # rather than settled: this writes the entry the way it was written before.
            table_page = bytearray(PAGE)
            struct.pack_into("<Q", table_page, 0x440, operand_va | (1 << 60))
            table_page = bytes(table_page)
        arena.alloc_at(low_va, PAGE, "control-operand-table", data=table_page,
                       flags=LOW_ALIAS_FLAGS)

        message = bytearray(g17p.CONTROL_MESSAGE_SIZE * 4)
        for index in range(3):
            struct.pack_into("<I", message, index * g17p.CONTROL_MESSAGE_SIZE,
                             g17p.CONTROL_MESSAGE_INIT)
        last = 3 * g17p.CONTROL_MESSAGE_SIZE
        struct.pack_into("<I", message, last + 0x00, 0x20)
        struct.pack_into("<I", message, last + 0x04, 1)
        struct.pack_into("<I", message, last + 0x08, 0x3f)
        struct.pack_into("<Q", message, last + 0x14, config_va)
        struct.pack_into("<Q", message, last + 0x1c, low_va)
        struct.pack_into("<Q", message, last + 0x24, low_va + 0x440)
        struct.pack_into("<I", message, last + 0x2c, 0x28)
        struct.pack_into("<I", message, last + 0x34, 1)
        print("  the 0x20 entry registers the shared control object at %#x" % config_va)
        return bytes(message), 4

    for slot, entry in enumerate(instances[:stage_count]):
        control = (g17p.CONTROL_MESSAGE_INIT if slot == 0
                   else g17p.CONTROL_MESSAGE_INIT_SECONDARY)
        if args.control_opcode is not None:
            # Does the entry's content matter at all? Firmware reads this ring while
            # accepting the descriptor and its consumer never moves, which reads the
            # same whether it rejects the entry or never looks at it. A deliberately
            # invalid opcode separates the two: if firmware is acting on content, an
            # invalid one has to change something, and if nothing changes then the
            # entry is not what it is refusing over.
            control = args.control_opcode
        channel = g17p.CHANNEL_TABLE_WORK_COUNT
        slot_pa = entry["control_ring_pa"]
        producer_pa = entry["channel_state_pas"][channel][
            g17p.CHANNEL_STATE_PRODUCER]
        if args.full_control and not args.defer_full_control and slot == 0:
            body, produced = build_full_control(entry)
        elif args.full_secondary_control and slot != 0:
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE
                             * sum(count for _, count in
                                   SECONDARY_CONTROL_SEQUENCE))
            produced = 0
            for opcode, count in SECONDARY_CONTROL_SEQUENCE:
                for _ in range(count):
                    struct.pack_into("<I", body,
                                     produced * g17p.CONTROL_MESSAGE_SIZE,
                                     opcode)
                    produced += 1
            body = bytes(body)
        else:
            body = bytearray(g17p.CONTROL_MESSAGE_SIZE * g17p.CONTROL_INIT_ENTRIES)
            for index in range(g17p.CONTROL_INIT_ENTRIES):
                struct.pack_into("<I", body, index * g17p.CONTROL_MESSAGE_SIZE,
                                 control)
            body, produced = bytes(body), g17p.CONTROL_INIT_ENTRIES
        iface.writemem(slot_pa, body)
        p.dc_civac(slot_pa, len(body))
        p.write32(producer_pa, produced)
        p.dc_civac(producer_pa, 8)
        if args.presume_control_consumed:
            # The only world observed to render presents the opening as already consumed: its
            # control counters read [4, 4, 4] before the initial kick, so firmware processes no
            # device-control entry at all. This host has always had firmware consume all four. The
            # difference has been present since this path was written and never tested.
            for index in range(g17p.CHANNEL_STATE_PRODUCER):
                pa = entry["channel_state_pas"][channel][index]
                if pa:
                    p.write32(pa, produced)
                    p.dc_civac(pa, 8)
            print("  presented %s control as already consumed at %d"
                  % (entry["name"], produced))
        if (args.full_control and slot == 0) and not args.defer_full_control:
            described = "three 0x16 then one 0x20"
        elif args.full_secondary_control and slot != 0:
            described = ", ".join("%d x %#x" % (count, opcode)
                                  for opcode, count in SECONDARY_CONTROL_SEQUENCE)
        else:
            described = "opcode %#x" % control
        print("  staged %s control %s, producer %d"
              % (entry["name"], described, produced))

    if args.seed_report_channels:
        for entry in instances:
            for channel, values in sorted(REPORT_CHANNEL_COUNTERS.items()):
                for index, value in enumerate(values):
                    pa = entry["channel_state_pas"][channel][index]
                    if pa:
                        p.write32(pa, value)
                        p.dc_civac(pa, 8)
            print("  seeded %s report channels %s" % (entry["name"],
                                                      REPORT_CHANNEL_COUNTERS))

    render_state = None
    if args.render_context:
        render_state = build_render_context(
            arena, uat, args.context, args.render_context,
            full_extent=args.full_render_extent,
            seed_all_render=args.seed_render_content)

    context_state = None
    if args.context_queue_state:
        context_state = build_context_queue_state(
            arena, uat, args.context, seed_from=args.seed_context_queue,
            phase=args.shared_control_phase)

    tail_state = None
    if args.descriptor_tails:
        tail_state = build_descriptor_tails(
            arena, uat, args.context, args.descriptor_tails, render_state,
            context_state)

    firmware_extent = None
    if args.firmware_extent:
        # Last, so that everything this path places itself is already in the arena and is left
        # alone; this only fills in the shape a host's firmware context has around it.
        firmware_extent = map_firmware_extent(
            arena, uat, args.context, args.firmware_extent,
            fill_blank=args.fill_blank_page)

    prestaged_backend = None
    if args.prestage_backend_group:
        prestaged_backend = prepare_backend_group(
            arena, asc, root_va, first_submit=True, render_state=render_state,
            context_state=context_state, tail_state=tail_state)

    seeded_native_pages = seed_native_pages(
        uat,
        args.context,
        args.seed_native_page_snapshot,
        args.seed_native_page,
    ) if args.seed_native_page else []

    if args.dump_closure:
        # From the descriptor root, which is what the message hands firmware, so the walk starts
        # where firmware starts. Walking from main_va instead compared a different root against
        # the snapshot's and made the cold world look shallower than it is.
        dump_initdata_closure(uat, args.context, instances[0]["root_va"], out)

    coproc_maint_pages = None
    if args.coproc_maint:
        coproc_maint_pages = coproc_maintain_pages(
            uat, arena, args.context, handoff_base, secondary_root)

    # Optional control/backend prestaging above can allocate mappings after the
    # initial descriptor-table flush. Publish every such mapping before either
    # firmware instance can consume initdata or a prestaged ring entry.
    if args.native_context_split and args.native_context_slots:
        # Now that every mapping exists, take the low root off the firmware slot and the high root
        # off the render slot, which is how a working host's root table reads. The tables
        # themselves are untouched; only which slot can reach each half changes.
        uat.set_l0(NATIVE_FIRMWARE_SLOT, 0, 0, NATIVE_FIRMWARE_CONTEXT)
        uat.set_l0(NATIVE_RENDER_SLOT, 1, 0, NATIVE_RENDER_CONTEXT)
        print("Applied the context split: firmware slot %d has no low root, render slot %d "
              "no high root" % (NATIVE_FIRMWARE_SLOT, NATIVE_RENDER_SLOT))

    uat.flush_dirty()
    uat.invalidate_cache()

    if args.build_before_run:
        print("Starting the coprocessors after UAT and initdata construction")
        for path in boot_paths:
            start_coprocessor(path)

    # Firmware writes into these objects when it accepts the descriptor. What it
    # writes has never been read out, and it is the only thing firmware volunteers
    # about its own state, so it is the natural place to look for a condition it
    # checks before it will serve a channel.
    init_before = snapshot_arena(arena) if args.reaction else None

    p.write32(sgx_base + g17p.SGX_PRE_INIT_REGISTER, 0)
    if args.capture_pre_initdata_state:
        message = InitMsg(TYPE=g17p.MSG_INITDATA,
                          INITDATA=instances[0]["root_va"] & ((1 << 44) - 1))
        phase_dir = out / "direct_pre_first_initdata"
        manifest = save_phase_state(
            iface, p, u.adt, phase_dir, "direct-pre-first-initdata",
            {
                "instance": instances[0]["name"],
                "payload": int(message.value),
                "descriptor_va": int(instances[0]["root_va"]),
            },
        )
        print("Captured direct pre-initdata state -> %s" % manifest)
        return 0
    init_count = args.init_instances if args.init_instances else len(ascs)
    if args.secondary_only:
        # Give a descriptor to the second instance alone. If it faults the same way
        # with the first instance untouched, the fault is intrinsic to it rather
        # than an interaction between the two.
        ascs = list(reversed(ascs))
        instances = list(reversed(instances))
        init_count = 1
    for index, (instance, entry) in enumerate(zip(ascs[:init_count],
                                                  instances[:init_count])):
        if args.native_sequence:
            instance.start_ep(0x20)
            instance.start_ep(0x21)
        message = InitMsg(TYPE=g17p.MSG_INITDATA,
                          INITDATA=entry["root_va"] & ((1 << 44) - 1))
        if args.capture_pre_secondary_initdata_state and index == 1:
            phase_dir = out / "direct_pre_secondary_initdata"
            manifest = save_phase_state(
                iface, p, u.adt, phase_dir,
                "direct-pre-secondary-initdata",
                {
                    "instance": entry["name"],
                    "payload": int(message.value),
                    "descriptor_va": int(entry["root_va"]),
                    "primary_acknowledged": bool(ascs[0].fw.acked),
                },
            )
            print("Captured direct pre-secondary-initdata state -> %s"
                  % manifest)
            return 0
        if args.patch_hwdata and index == 0:
            # The other side of the same comparison: scalars in the hardware-data bundle
            # that a working host sets differently. Several look like clock and thermal
            # values, so this is as much about closing the candidate as about fixing it.
            print("  patching the hardware-data bundle at %#x" % hwdata_va)
            for offset, value in args.patch_hwdata:
                before = struct.unpack("<I", iface.readmem(hwdata_pa + offset, 4))[0]
                iface.writemem(hwdata_pa + offset, struct.pack("<I", value))
                print("    +%#06x  %#010x -> %#010x" % (offset, before, value))
            p.dc_civac(hwdata_pa, g17p.HWDATA_BUNDLE_ALLOC_SIZE)

        if args.patch_data_region and index == 0:
            # Comparing the cold world's scalars against a working one showed fields in the
            # data region that a working host sets and this path leaves zero. This writes
            # them before firmware ever reads the descriptor.
            def arena_physical(dva):
                for record in arena.entries:
                    if record["va"] <= dva < record["va"] + record["size"]:
                        return record["pa"] + (dva - record["va"])
                return None

            root_pa = arena_physical(int(entry["root_va"]))
            region = struct.unpack("<Q", iface.readmem(root_pa + 0x20, 8))[0]
            region_pa = arena_physical(region)
            if region_pa is None:
                raise RuntimeError("the data region at %#x is not in the arena" % region)
            print("  patching the data region at %#x" % region)
            for offset, value in args.patch_data_region:
                before = struct.unpack("<I", iface.readmem(region_pa + offset, 4))[0]
                iface.writemem(region_pa + offset, struct.pack("<I", value))
                print("    +%#06x  %#010x -> %#010x" % (offset, before, value))
            p.dc_civac(region_pa & ~(PAGE - 1), PAGE)

        if args.patch_status_a and index == 0:
            # Upstream of the register array, and so still in scope after that was excluded. A
            # working world has `0x205` at this block's `+0x00` where this path has zero.
            print("  patching the status block at %#x" % status_a_pa)
            for offset, value in args.patch_status_a:
                before = struct.unpack(
                    "<I", iface.readmem(status_a_pa + offset, 4))[0]
                iface.writemem(status_a_pa + offset, struct.pack("<I", value))
                print("    +%#06x  %#010x -> %#010x" % (offset, before, value))
            p.dc_civac(status_a_pa & ~(PAGE - 1), PAGE)

        if args.patch_main_config and index == 0:
            # The same comparison in the main configuration object. Two words there are set by a
            # working host and left zero here, one of them a magic value, and neither is an
            # address, so neither can be found by walking the graph.
            def arena_physical_main(dva):
                for record in arena.entries:
                    if record["va"] <= dva < record["va"] + record["size"]:
                        return record["pa"] + (dva - record["va"])
                return None

            root_pa = arena_physical_main(int(entry["root_va"]))
            main_object = struct.unpack(
                "<Q", iface.readmem(root_pa + build.ROOT_MAIN_CONFIG, 8))[0]
            main_object_pa = arena_physical_main(main_object)
            if main_object_pa is None:
                raise RuntimeError(
                    "the main object at %#x is not in the arena" % main_object)
            print("  patching the main configuration object at %#x" % main_object)
            for offset, value in args.patch_main_config:
                before = struct.unpack(
                    "<I", iface.readmem(main_object_pa + offset, 4))[0]
                iface.writemem(main_object_pa + offset, struct.pack("<I", value))
                print("    +%#06x  %#010x -> %#010x" % (offset, before, value))
            p.dc_civac(main_object_pa & ~(PAGE - 1), PAGE)

        print("Sending initdata to %s: %#x" % (entry["name"], int(message.value)))
        instance.fw.send(message)
        if ((args.serialise_init or args.capture_pre_secondary_initdata_state)
                and index + 1 < len(ascs)):
            # Whether an instance has to be acknowledged before the next is given
            # its descriptor is not recorded either way, so it is an option here
            # rather than an assumption.
            wait = time.time() + args.timeout
            while time.time() < wait and not instance.fw.acked:
                try:
                    instance.work_pending()
                except Exception as exc:
                    print("  %s CRASHED while waiting: %s" % (entry["name"], exc))
                    break
                time.sleep(0.02)
            print("  %s %s before the next instance"
                  % (entry["name"],
                     "acknowledged" if instance.fw.acked else "did not reply"))

    deadline = time.time() + args.timeout
    crashed = {}
    waited = ascs[:init_count]
    while time.time() < deadline and not all(i.fw.acked for i in waited):
        for instance, entry in zip(waited, instances):
            if entry["name"] in crashed:
                continue
            try:
                instance.work_pending()
            except Exception as exc:
                # Say which instance died. Both are polled here, so an unlabelled
                # crash report cannot be attributed to either one.
                crashed[entry["name"]] = str(exc)
                print("  %s CRASHED: %s" % (entry["name"], exc))
        if len(crashed) == len(waited):
            break
        time.sleep(0.05)
    for instance, entry in zip(waited, instances):
        print("  %s: %s" % (entry["name"],
                            "acknowledged" if instance.fw.acked else "no reply"))

    if args.crash_at == "after-ack":
        # Provoke a fault deliberately and read the report. Firmware reacts visibly
        # to a message type it does not know, which is the only way found so far to
        # get its internal state out. Taking the report here and again after the
        # start notification says whether that notification changes anything inside
        # firmware, given that it changes nothing in memory.
        print("Provoking a fault after the acknowledgement")
        ascs[0].db.send(DoorbellMsg(TYPE=0xff, CHANNEL=0x11))
        for _ in range(40):
            try:
                ascs[0].work_pending()
            except Exception as exc:
                print("  primary faulted: %s" % exc)
                break
            time.sleep(0.05)
        return 0

    acked = all(i.fw.acked for i in waited)
    post_ack_crashed = {}
    if acked and args.post_ack_observe_ms:
        deadline_observe = time.time() + args.post_ack_observe_ms / 1000.0
        while time.time() < deadline_observe:
            for instance, entry in zip(waited, instances):
                if entry["name"] in post_ack_crashed:
                    continue
                try:
                    instance.work_pending()
                except Exception as exc:
                    post_ack_crashed[entry["name"]] = str(exc)
                    print("  %s CRASHED during post-ack observation: %s"
                          % (entry["name"], exc))
            time.sleep(0.001)
        print("  post-ack events: %s"
              % ", ".join("%s=%d" % (entry["name"], instance.fw.events)
                          for instance, entry in zip(waited, instances)))
    if init_before is not None:
        changed = diff_snapshots(init_before, snapshot_arena(arena),
                                 "at the descriptor")
        # Context around whatever firmware touched, plus the table entry whose
        # region it landed in. A byte on its own says where firmware wrote; the
        # surrounding words say what it thinks the region is.
        for name, spans, _first, second in changed:
            for start, _end in spans[:4]:
                base = max(0, (start & ~0xf) - 0x20)
                window = second[base:base + 0x60]
                print("    %s context at %#06x:" % (name, base))
                for row in range(0, len(window), 16):
                    print("      %#06x  %s" % (base + row,
                                               window[row:row + 16].hex(" ")))
        print("  channel table as built:")
        for index in range(build.CHANNEL_TABLE_ENTRIES):
            states, ring = instances[0]["channels"][index]
            label = (g17p.CHANNEL_TABLE_WORK_ORDER[index]
                     if index < g17p.CHANNEL_TABLE_WORK_COUNT else "ch%d" % index)
            offset = (ring - instances[0]["ring_va"]) if ring else None
            print("    %-5s states %s ring %s%s"
                  % (label, " ".join("%#x" % a if a else "0" for a in states),
                     "%#x" % ring if ring else "0",
                     "" if offset is None else "  (ring offset %#x)" % offset))
    def read_channel_state(entry, channel):
        values = []
        for pa in entry["channel_state_pas"][channel]:
            if not pa:
                values.append(0)
                continue
            p.dc_civac(pa, 4)
            values.append(struct.unpack("<I", bytes(iface.readmem(pa, 4)))[0])
        return tuple(values)

    post_control_start_crashed = {}
    control_start_indices = []
    opening_control_counters = {}
    if acked and not args.no_control:
        # Only initialized instances are told to begin servicing their rings. The
        # message is the type alone with a zero channel field.
        if args.control_start_order is None:
            control_start_count = (args.control_start_instances
                                   if args.control_start_instances else len(waited))
            control_start_indices = list(range(
                args.control_start_offset,
                args.control_start_offset + control_start_count,
            ))
        else:
            try:
                control_start_indices = [int(value, 0) for value in
                                         args.control_start_order.split(",")]
            except ValueError:
                parser.error("--control-start-order must be comma-separated "
                             "integer indices")
            if not control_start_indices:
                parser.error("--control-start-order must name at least one ASC")
            if len(set(control_start_indices)) != len(control_start_indices):
                parser.error("--control-start-order cannot repeat an ASC index")
        if any(index < 0 or index >= len(waited)
               for index in control_start_indices):
            parser.error("--control-start-order/offset selects an uninitialized "
                         "ASC")
        control_started = [waited[index] for index in control_start_indices]
        for position, instance in enumerate(control_started):
            instance.db.send(DoorbellMsg(TYPE=g17p.MSG_CONTROL_START,
                                         CHANNEL=g17p.CONTROL_START_CHANNEL))
            if (args.control_start_gap_ms and
                    position + 1 < len(control_started)):
                time.sleep(args.control_start_gap_ms / 1000.0)
        for _ in range(10):
            # A control-start message sent to one ASC can make the other emit its
            # crash notification. Poll the whole initialized pair so an experiment
            # records the endpoint rather than stopping before it writes its result.
            for instance, entry in zip(waited, instances):
                if entry["name"] in post_control_start_crashed:
                    continue
                try:
                    instance.work_pending()
                except Exception as exc:
                    post_control_start_crashed[entry["name"]] = str(exc)
                    print("  %s CRASHED during control start: %s"
                          % (entry["name"], exc))
            time.sleep(0.001)
        print("  control start sent to %d initialized instances"
              % len(control_started))
        counter_deadline = time.time() + 0.02
        while time.time() < counter_deadline:
            opening_control_counters = {
                entry["name"]: read_channel_state(
                    entry, g17p.CHANNEL_TABLE_WORK_COUNT)
                for entry in instances[:len(waited)]
            }
            if all(values == (1, 1, 1)
                   for values in opening_control_counters.values()):
                break
            time.sleep(0.001)
        print("  opening control counters: %s"
              % ", ".join("%s=%s" % (name, values)
                          for name, values in opening_control_counters.items()))

    if acked and args.post_control_start_observe_ms:
        deadline_observe = (time.time()
                            + args.post_control_start_observe_ms / 1000.0)
        while time.time() < deadline_observe:
            for instance, entry in zip(waited, instances):
                if entry["name"] in post_control_start_crashed:
                    continue
                try:
                    instance.work_pending()
                except Exception as exc:
                    post_control_start_crashed[entry["name"]] = str(exc)
                    print("  %s CRASHED during post-control-start observation: %s"
                          % (entry["name"], exc))
            time.sleep(0.001)
        print("  post-control-start events: %s"
              % ", ".join("%s=%d" % (entry["name"], instance.fw.events)
                          for instance, entry in zip(waited, instances)))

    deferred_control = None
    if (acked and args.defer_full_control and
            not post_control_start_crashed):
        primary = instances[0]
        body, produced = build_full_control(primary)
        uat.flush_dirty()
        uat.invalidate_cache()
        iface.writemem(primary["control_ring_pa"], body)
        p.dc_civac(primary["control_ring_pa"], len(body))
        producer_pa = primary["channel_state_pas"][
            g17p.CHANNEL_TABLE_WORK_COUNT][g17p.CHANNEL_STATE_PRODUCER]
        p.write32(producer_pa, produced)
        p.dc_civac(producer_pa, 8)
        deferred_control = {
            "producer": produced,
            "opening_counters": list(opening_control_counters["primary"]),
        }
        print("  staged primary control entries 1-3 after opening, producer %d"
              % produced)

    if acked and args.stop_after_control_start:
        (out / "control_start.json").write_text(json.dumps({
            "format": "m1n1-t8140-g17p-control-start-v2",
            "acknowledged": True,
            "control_start_instances": len(control_start_indices),
            "control_start_offset": args.control_start_offset,
            "control_start_order": control_start_indices,
            "control_start_gap_ms": args.control_start_gap_ms,
            "opening_control_counters": {
                name: list(values)
                for name, values in opening_control_counters.items()
            },
            "deferred_control": deferred_control,
            "post_control_start_crashed": post_control_start_crashed,
        }, indent=2, sort_keys=True) + "\n")
        print("RESULT: acknowledged; stopped after control start")
        return 0

    print("RESULT: %s" % ("acknowledged" if acked else "no acknowledgement"))

    if acked and args.dump_post_ack:
        # What firmware wrote into the objects it was handed, in full, so it can be diffed against
        # a working world's. Every comparison so far has been of the two worlds' inputs; this is
        # their output, and the capture is itself post-acknowledgement, so the two are comparable.
        post_ack = out / "post_ack"
        post_ack.mkdir(exist_ok=True)

        def arena_pa(dva):
            for record in arena.entries:
                if record["va"] <= dva < record["va"] + record["size"]:
                    return record["pa"] + (dva - record["va"])
            return None

        # The objects the opening sequence acts on, so a run can say whether the `0x20` was acted
        # on rather than only whether its entry was counted. Firmware advances the shared control
        # object's cursor from 0x88 to 0xb0 and its inner object's first byte from 1 to 2.
        extra = []
        for name, dva, size in (
                ("shared_control", SHARED_CONTROL_ADDRESS, 0x80),
                ("shared_control_inner", SHARED_CONTROL_INNER_ADDRESS, 0x40),
                ("operand_table", 0x0000007000208000, 0x800),
                ("control_ring", 0, 0)):
            if name == "control_ring":
                extra.append((name, instances[0]["control_ring_pa"], 0x200))
                continue
            pa = arena_pa(dva)
            if pa is not None:
                extra.append((name, pa, size))
            else:
                print("  %s at %#x is not in the arena, not saved" % (name, dva))

        written = {}
        for name, pa, size in (("root", root_pa, 0x100),
                               ("main_config", main_pa, 0x600),
                               ("data_region", region_c_pa, 0x1000),
                               ("status_a", status_a_pa, 0x400),
                               ("status_b", status_b_pa, 0x400)) + tuple(extra):
            p.dc_civac(pa & ~(PAGE - 1), (size + PAGE - 1) & ~(PAGE - 1))
            body = bytes(iface.readmem(pa, size))
            (post_ack / (name + ".bin")).write_bytes(body)
            written[name] = {"pa": pa, "size": size,
                             "nonzero": sum(byte != 0 for byte in body)}
            print("  saved %-12s %#x bytes, %d non-zero"
                  % (name, size, written[name]["nonzero"]))
        (post_ack / "manifest.json").write_text(
            json.dumps(written, indent=2, sort_keys=True) + "\n")
        # The two phase fields, read out directly, because whether the opening was acted on is the
        # question a counter cannot answer.
        shared = (post_ack / "shared_control.bin")
        inner = (post_ack / "shared_control_inner.bin")
        if shared.exists() and inner.exists():
            cursor = struct.unpack_from("<I", shared.read_bytes(),
                                        SHARED_CONTROL_COUNT_AT)[0]
            flag = inner.read_bytes()[0]
            # The verdict only means anything when the host built the before values. Having built
            # the after values, reading them back says nothing about what firmware did, and a
            # witness that reports the host's own writes is worse than none.
            if args.shared_control_phase == "after":
                verdict = ("no verdict: this run built the after values, so these are the "
                           "host's own writes")
            elif cursor == SHARED_CONTROL_COUNT_AFTER or flag == SHARED_CONTROL_INNER_AFTER:
                verdict = "the 0x20 was ACTED ON by firmware"
            else:
                verdict = "the 0x20 was counted but not acted on"
            print("  shared control cursor %#x (before %#x, after %#x); inner byte %d "
                  "(before %d, after %d)  -> %s"
                  % (cursor, SHARED_CONTROL_COUNT_BEFORE, SHARED_CONTROL_COUNT_AFTER,
                     flag, SHARED_CONTROL_INNER_BEFORE, SHARED_CONTROL_INNER_AFTER,
                     verdict))
        # Whether firmware has looked at the work yet. The world that renders has consumed and
        # executed it by this point, before any doorbell; this path has assumed the same and never
        # measured it. If these are still at their staged values, the prestaging is not achieving
        # what it is for and every "work present when firmware starts" reading needs revisiting.
        if prestaged_backend is not None:
            for channel, label in ((0, "TA_0"), (1, "3D_0")):
                values = []
                for pa in instances[0]["channel_state_pas"][channel][:3]:
                    if not pa:
                        values.append(0)
                        continue
                    p.dc_civac(pa, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(pa, 4)))[0])
                print("  at acknowledgement, %s counters %s" % (label, values))
            for name in sorted(prestaged_backend["queues"]):
                print("  at acknowledgement, %s queue indices %s"
                      % (name, prestaged_backend["queues"][name].indices()))
        # Every page this path placed itself that the capture also has, so the two firmware
        # contexts can be diffed page by page rather than object by object. The five top-level
        # objects have been compared; the rings, the channel state blocks, the item rings, the
        # pools and the items have not, and any of them could hold a difference no object-level
        # comparison would reach.
        context_dir = post_ack / "firmware_context"
        context_dir.mkdir(exist_ok=True)
        saved = {}
        seen_pages = set()
        for record in arena.entries:
            base = record["va"] & ~(PAGE - 1)
            for offset in range(0, record["size"] + (record["va"] - base), PAGE):
                page_va = base + offset
                if page_va in seen_pages or page_va < 0xfffffc2000000000:
                    continue
                if page_va >= 0xfffffc2200000000:
                    continue
                seen_pages.add(page_va)
                page_pa = record["pa"] - (record["va"] - base) + offset
                p.dc_civac(page_pa, PAGE)
                body = bytes(iface.readmem(page_pa, PAGE))
                if not any(body):
                    continue
                (context_dir / ("%016x.bin" % page_va)).write_bytes(body)
                saved["%#x" % page_va] = {"pa": page_pa,
                                          "nonzero": sum(b != 0 for b in body)}
        (context_dir / "manifest.json").write_text(
            json.dumps(saved, indent=2, sort_keys=True) + "\n")
        print("  saved %d non-empty firmware-context pages of %d walked -> %s"
              % (len(saved), len(seen_pages), context_dir))
        print("Saved the post-acknowledgement state -> %s" % post_ack)

    if acked and args.dump_state:
        # Firmware writes into the objects it was handed. Reading them back after the
        # acknowledgement says what state it thinks it is in, which is the question
        # when it accepts the descriptor but then services nothing.
        print("State firmware wrote back:")
        for name, pa, size in (("status_a", status_a_pa, 0x80),
                               ("status_b", status_b_pa, 0x80),
                               ("region_c", region_c_pa, 0x80),
                               ("root", root_pa, 0xc0),
                               ("main_config", main_pa, 0x40)):
            blob = iface.readmem(pa, size)
            nonzero = [(o, struct.unpack_from("<Q", blob, o)[0])
                       for o in range(0, size, 8)
                       if struct.unpack_from("<Q", blob, o)[0]]
            print("  %-12s %d of %d words set%s"
                  % (name, len(nonzero), size // 8,
                     ":" if nonzero else ""))
            for o, v in nonzero[:12]:
                print("      +%#04x %#018x" % (o, v))

    if args.registers:
        # The same probes the live capture takes, read here where there is no trap
        # to hold open. A working host writes none of these before the descriptor,
        # so any difference came from how the machine was brought up.
        # Widened from four offsets to sixteen so this is directly comparable with the same probe
        # on the replay path. Whether the accelerator is running has only ever been inferred here
        # from whether it wrote anything, and a halted accelerator produces exactly this path's
        # symptom: firmware's bookkeeping advances and nothing is drawn.
        probes = [(base, off) for base in g17p.REGISTER_WINDOW_BASES
                  for off in range(0x0, 0x40, 4)]
        values = {}
        for base, off in probes:
            try:
                values["%#x+%#x" % (base, off)] = int(p.read32(base + off))
            except Exception:
                pass
        path = out / "registers.json"
        path.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n")
        print("Read %d accelerator registers -> %s" % (len(values), path))

    control_result = None
    if acked and not args.no_control and prestaged_backend is None:
        # The device-control channel is the entry that continues the work-channel
        # state grid. Its messages are twice the width of a work ring slot, and the
        # first thing a live host sends on it is the type below, so that is what is
        # sent here. Publication follows the order already established for the work
        # channels: message first, then the producer counter, then the doorbell.
        entry = g17p.CHANNEL_TABLE_WORK_COUNT
        slot_pa = ring_pa + g17p.RING_STRIDE * g17p.CHANNEL_TABLE_WORK_COUNT
        producer_pa = instances[0]["channel_state_pas"][entry][
            g17p.CHANNEL_STATE_PRODUCER]
        consumer_pa = instances[0]["channel_state_pas"][entry][
            g17p.CHANNEL_STATE_CONSUMER]

        # The message was staged before the descriptor was handed over, so nothing
        # is written here; this only notifies and then watches the counters.

        def all_counters():
            # Firmware writes these counters, so a read has to go past whatever the
            # host has cached for the line. Reading without invalidating shows the
            # host's own last write forever and looks exactly like a channel that is
            # never serviced.
            counters = []
            for state_pas in instances[0]["channel_state_pas"]:
                values = []
                for pa in state_pas:
                    if not pa:
                        values.append(0)
                        continue
                    p.dc_civac(pa, 4)
                    values.append(struct.unpack(
                        "<I", bytes(iface.readmem(pa, 4)))[0])
                counters.append(tuple(values))
            return counters

        if args.sweep_control:
            # Which doorbell number reaches this channel is not established for this
            # part, so ring every plausible number once and watch every counter. One
            # boot answers it; guessing costs a boot per guess.
            base_all = all_counters()
            hits = []
            for candidate in range(args.sweep_control):
                asc.db.send(DoorbellMsg(TYPE=args.control_type,
                                        CHANNEL=candidate))
                time.sleep(0.05)
                asc.work_pending()
                now = all_counters()
                if now != base_all:
                    changed = [(e, base_all[e], now[e])
                               for e in range(build.CHANNEL_TABLE_ENTRIES)
                               if base_all[e] != now[e]]
                    hits.append((candidate, changed))
                    print("  doorbell %#04x moved: %s"
                          % (candidate, ", ".join("ch%d %s->%s" % (e, a, b)
                                                  for e, a, b in changed)))
                    base_all = now
            if not hits:
                print("  no doorbell number 0..%#x moved any counter"
                      % (args.sweep_control - 1))
            control_result = {"swept": args.sweep_control,
                              "hits": [[c, [[e, list(a), list(b)]
                                            for e, a, b in ch]] for c, ch in hits],
                              "events": asc.fw.events}
            print("  events seen during sweep: %d" % asc.fw.events)
            (out / "coldboot.json").write_text(json.dumps({
                "format": "m1n1-t8140-g17p-coldboot-v1",
                "build_before_run": bool(args.build_before_run),
                "control": control_result,
                "coproc_maint_pages": coproc_maint_pages,
                "allocations": arena.entries,
            }, indent=2, sort_keys=True) + "\n")
            return 0

        if args.sweep_types:
            # The channel number has been swept with the message type held at the
            # opening kick. The type itself never has, and firmware is now known to
            # service no ring at all after acknowledging, so the question is no longer
            # which channel to name but whether any message at all moves it. One boot
            # covers the whole range: send each type, then look for a counter moving
            # anywhere or any handed byte changing.
            print("Sweeping message types on the doorbell endpoint")
            sweep_before = snapshot_arena(arena)
            sweep_base = all_counters()
            moved_by = []
            for message_type in args.sweep_types:
                try:
                    asc.db.send(DoorbellMsg(TYPE=message_type,
                                            CHANNEL=g17p.CONTROL_START_CHANNEL))
                    for _ in range(4):
                        asc.work_pending()
                        time.sleep(0.01)
                except Exception as error:
                    print("  type %#04x provoked: %s" % (message_type, error))
                    moved_by.append((message_type, "faulted"))
                    break
                now = all_counters()
                changed = [e for e in range(build.CHANNEL_TABLE_ENTRIES)
                           if sweep_base[e] != now[e]]
                if changed:
                    print("  type %#04x moved channels %s"
                          % (message_type, changed))
                    moved_by.append((message_type, changed))
                    sweep_base = now
            touched = diff_snapshots(sweep_before, snapshot_arena(arena),
                                     "across the whole type sweep")
            if not moved_by:
                print("  none of %d types moved any counter" % len(args.sweep_types))
            (out / "coldboot.json").write_text(json.dumps({
                "format": "m1n1-t8140-g17p-coldboot-v1",
                "build_before_run": bool(args.build_before_run),
                "type_sweep": {"types": args.sweep_types,
                               "moved_by": [[t, str(c)] for t, c in moved_by],
                               "objects_touched": [name for name, _s, _a, _b
                                                   in touched]},
                "allocations": arena.entries,
            }, indent=2, sort_keys=True) + "\n")
            return 0

        # Staged before the snapshot below on purpose. This host's own producer write
        # would otherwise land inside the diff window and be reported as memory
        # firmware touched, which is exactly the confusion this diff exists to avoid.
        if args.stage_work is not None:
            # Does the scheduler only look at the device-control ring while it is
            # doing a work pass? Every notification so far has been sent with all
            # twelve work channels empty, so a scheduler that scans work first and
            # gives up when there is none would look exactly like one declining the
            # control entry. Publishing on a work channel distinguishes the two: if
            # a consumer moves anywhere, the scheduler does scan when it has reason
            # to, and the control ring's problem is a separate one.
            #
            # The work item is not constructed, only the producer index moved. A
            # malformed item is fine and a fault would be informative; what is being
            # measured is whether firmware looks, not whether it succeeds.
            work_channel = args.stage_work
            work_producer = instances[0]["channel_state_pas"][work_channel][
                g17p.CHANNEL_STATE_PRODUCER]
            p.write32(work_producer, 1)
            p.dc_civac(work_producer, 8)
            # The low bits carry the queue and kind, so channel N kind 0 is N << 2.
            asc.db.send(DoorbellMsg(TYPE=g17p.MSG_WORK_DOORBELL,
                                    CHANNEL=(work_channel << 2)))
            print("  published on work channel %d and rang its doorbell"
                  % work_channel)
            for _ in range(20):
                asc.work_pending()
                time.sleep(0.05)

        if args.settle:
            # Firmware may not be ready to serve the instant it acknowledges. On a
            # live system the kick arrives well after the acknowledgement, with a
            # lot of other work in between; here it follows immediately.
            print("  letting firmware settle for %.1fs" % args.settle)
            deadline_settle = time.time() + args.settle
            while time.time() < deadline_settle:
                for i in waited:
                    i.work_pending()
                time.sleep(0.05)

        # What does firmware actually do when it gets the kick? It takes the message
        # out of the mailbox and answers nothing, but whether it touches any of the
        # memory it was handed has never been checked. A diff across the
        # notification says how far it got, and costs one bulk read either side.
        objects_before = snapshot_arena(arena) if args.reaction else None

        before_all = all_counters()
        before = before_all[entry][g17p.CHANNEL_STATE_CONSUMER]
        # A first doorbell only wakes firmware when it has gone idle; the second is
        # the one it acts on. This is the same behaviour the work channels show.
        for attempt in range(args.notify_repeat):
            if args.native_kick:
                # What a live host actually rings, taken from its own AP->IOP
                # mailbox log rather than from a guess: type 0x84 carrying the
                # control channel 0x11, and then type 0x83 for channel zero. The
                # opening kick tried until now, type 0x89 with channel zero, does
                # not appear in that log at all, and the pair has only ever been
                # sent in the opposite order.
                asc.db.send(DoorbellMsg(TYPE=g17p.MSG_CONTROL_DONE,
                                        CHANNEL=g17p.CONTROL_DOORBELL_CHANNEL))
                for _ in range(4):
                    asc.work_pending()
                    time.sleep(0.02)
                asc.db.send(DoorbellMsg(TYPE=g17p.MSG_WORK_DOORBELL,
                                        CHANNEL=g17p.CONTROL_START_CHANNEL))
                if attempt + 1 < args.notify_repeat:
                    for _ in range(10):
                        asc.work_pending()
                        time.sleep(0.05)
                continue
            asc.db.send(DoorbellMsg(TYPE=args.control_type,
                                    CHANNEL=args.control_channel))
            if args.also_notify:
                # A live system sends the opening kick once and then a per-publish
                # notification with the channel number for every entry it adds.
                # Each has been tried alone here; the pair in order has not.
                for _ in range(4):
                    asc.work_pending()
                    time.sleep(0.02)
                asc.db.send(DoorbellMsg(TYPE=g17p.MSG_CONTROL_DONE,
                                        CHANNEL=g17p.CONTROL_DOORBELL_CHANNEL))
            if attempt + 1 < args.notify_repeat:
                for _ in range(10):
                    asc.work_pending()
                    time.sleep(0.05)
        # Whether firmware even takes the notification out of the mailbox has been
        # assumed, not checked. If it sits in the inbox the problem is upstream of
        # anything to do with the ring.
        if args.probe_endpoint:
            # Is the doorbell endpoint alive on our side at all? Every legitimate
            # notification produces no reaction whatever, which looks the same as
            # messages being dropped for an endpoint that was never started. An
            # unknown message type should provoke something from a live endpoint;
            # from a dead one it will be as silent as the rest.
            before_probe = snapshot_arena(arena)
            asc.db.send(DoorbellMsg(TYPE=0xff, CHANNEL=0x11))
            for _ in range(20):
                try:
                    asc.work_pending()
                except Exception as exc:
                    print("  unknown type provoked: %s" % exc)
                    break
                time.sleep(0.05)
            diff_snapshots(before_probe, snapshot_arena(arena),
                           "after an unknown message type")
            probe_inbox = asc.asc.INBOX_CTRL.reg
            print("  inbox after unknown type: empty=%d rptr=%d wptr=%d"
                  % (probe_inbox.EMPTY, probe_inbox.RPTR, probe_inbox.WPTR))

        if args.answer_23:
            # The scheduler emits exactly one message when it wakes, on a mailbox
            # separate from the one the host talks on, addressed to endpoint 0x23,
            # and nothing ever answers it. Endpoint 0x23 is not in the map firmware
            # advertises, so a host is not expected to serve it, and the peer
            # instance is the natural other party. But the peer faults on its own
            # post-init path before this point in every configuration tried, so
            # whether the scheduler is *waiting* on that reply has never been
            # testable. Answering it from here settles that: if the scheduler is
            # blocked on a reply, one arriving has to change what it does next.
            for payload in args.answer_23:
                asc.send(payload, ASCMessage1(EP=g17p.PEER_ENDPOINT))
                print("  answered endpoint %#x with %#x"
                      % (g17p.PEER_ENDPOINT, payload))
                for _ in range(10):
                    asc.work_pending()
                    time.sleep(0.05)

        if args.scan_mailboxes:
            # Firmware queued one message on a mailbox the host does not use, and
            # nothing drained it, so that mailbox's control register should still
            # report a message waiting. m1n1 maps exactly one mailbox, control at
            # +0x8110 and +0x8114 with data at +0x8800 and +0x8830, so any second
            # one is elsewhere in the same control block. A register that decodes as
            # a mailbox control and reports non-empty identifies it.
            print("Scanning the control block for a mailbox the host does not use")
            for path in paths:
                base = int(u.adt[path].get_reg(0)[0])
                found = []
                for off in range(0x8100, 0x8200, 4):
                    value = int(p.read32(base + off))
                    if value == 0 or value == 0xffffffff:
                        continue
                    reg = R_MBOX_CTRL(value)
                    # A control register carries a count and empty/full flags; a
                    # non-empty one with a plausible count is the interesting case.
                    if reg.FIFOCNT or not reg.EMPTY:
                        found.append((off, value, reg.FIFOCNT, reg.EMPTY,
                                      reg.RPTR, reg.WPTR, reg.ENABLE))
                print("  %s:" % path)
                for off, value, cnt, empty, rptr, wptr, enable in found:
                    print("    +%#06x = %#010x  fifocnt=%d empty=%d rptr=%d "
                          "wptr=%d enable=%d%s"
                          % (off, value, cnt, empty, rptr, wptr, enable,
                             "   <- the mailbox m1n1 uses"
                             if off in (0x8110, 0x8114) else ""))
                if not found:
                    print("    no control register reports a waiting message")
                # The mailbox m1n1 uses has its data at +0x8800/+0x8808 for the
                # inbox and +0x8830/+0x8838 for the outbox, and its control at
                # +0x8110/+0x8114. If +0x8118 and +0x811c are a second pair's
                # control, that pair's data should follow the same stride. Dump the
                # range and look for the peer message, which is the one thing known
                # to be sitting in a mailbox the host does not read.
                print("    data registers:")
                for off in range(0x8800, 0x8860, 8):
                    value = int(p.read64(base + off))
                    if not value:
                        continue
                    note = {0x8800: "inbox message", 0x8808: "inbox endpoint",
                            0x8830: "outbox message",
                            0x8838: "outbox endpoint"}.get(off, "")
                    peer = ""
                    if (value & 0xff) == g17p.PEER_ENDPOINT:
                        peer = "   <- endpoint %#x" % g17p.PEER_ENDPOINT
                    print("      +%#06x = %#018x  %s%s" % (off, value, note, peer))

        inbox = asc.asc.INBOX_CTRL.reg
        print("  inbox after notify: empty=%d fifocnt=%d rptr=%d wptr=%d"
              % (inbox.EMPTY, inbox.FIFOCNT, inbox.RPTR, inbox.WPTR))

        deadline = time.time() + args.timeout
        after_all = before_all
        while time.time() < deadline:
            asc.work_pending()
            after_all = all_counters()
            if after_all != before_all:
                break
            time.sleep(0.05)
        after = after_all[entry][g17p.CHANNEL_STATE_CONSUMER]
        moved = [(e, before_all[e], after_all[e])
                 for e in range(build.CHANNEL_TABLE_ENTRIES)
                 if before_all[e] != after_all[e]]
        if objects_before is not None:
            diff_snapshots(objects_before, snapshot_arena(arena),
                           "at the notification")

        # Report what was actually rung, not the defaults: --native-kick ignores
        # both of these and a report naming them would be wrong.
        if args.native_kick:
            kicked = ("type %#x channel %#x then type %#x channel %#x"
                      % (g17p.MSG_CONTROL_DONE, g17p.CONTROL_DOORBELL_CHANNEL,
                         g17p.MSG_WORK_DOORBELL, g17p.CONTROL_START_CHANNEL))
        else:
            kicked = "type %#x channel %#x" % (args.control_type,
                                               args.control_channel)
        control_result = {"channel": args.control_channel,
                          "native_kick": args.native_kick,
                          "kicked": kicked,
                          "consumer_before": before, "consumer_after": after,
                          "consumed": after != before,
                          "moved": [[e, list(a), list(b)] for e, a, b in moved]}
        print("CONTROL: notify %s, counters %s -> %s, %s"
              % (kicked, before_all[entry], after_all[entry],
                 "consumed" if after != before else "not consumed"))
        for e, a, b in moved:
            print("  channel %d counters %s -> %s" % (e, a, b))
        if not moved:
            print("  no channel counter moved, events seen: %d" % asc.fw.events)

        if args.crash_at == "after-notify":
            print("Provoking a fault after the declined notification")
            asc.db.send(DoorbellMsg(TYPE=0xff, CHANNEL=0x11))
            for _ in range(40):
                try:
                    asc.work_pending()
                except Exception as exc:
                    print("  primary faulted: %s" % exc)
                    break
                time.sleep(0.05)

    control_ticks = {}
    if args.control_tick_before:
        print("Publishing device-control ticks before the work doorbell")
        control_ticks["before"] = control_channel_tick(
            instances[0], asc, args.control_tick_before, 0, "tick before")

    backend_result = None
    if prestaged_backend is not None:
        backend_result = finish_backend_group(prestaged_backend)
    elif args.publish_backend_group:
        backend_result = publish_backend_group(arena, asc, root_va, args)

    if args.control_tick_after:
        print("Publishing device-control ticks after the work doorbell")
        control_ticks["after"] = control_channel_tick(
            instances[0], asc, args.control_tick_after,
            args.control_tick_before, "tick after")

    render_witness = None
    if render_state is not None:
        # A submission can be accepted, scheduled and retired without drawing, so the
        # counters are not the render witness. These pages are.
        deadline = time.time() + 0.5
        while time.time() < deadline:
            with contextlib.suppress(Exception):
                asc.work_pending()
            time.sleep(0.01)
        render_witness = read_render_witness(render_state, "after publication")

    (out / "coldboot.json").write_text(json.dumps({
        "backend_group": backend_result,
        "firmware_extent": firmware_extent,
        "control_ticks": control_ticks,
        "context_queue_state": None if context_state is None else {
            "pointers": {
                kind: {name: "%#x" % value for name, value in pointers.items()}
                for kind, pointers in context_state["pointers"].items()
            },
        },
        "render_context": None if render_state is None else {
            "pages": render_state["pages"],
            "tiling_writes": len(render_state["registers"]["tiling"]),
            "fragment_writes": len(render_state["registers"]["fragment"]),
            "witness": render_witness,
        },
        "format": "m1n1-t8140-g17p-coldboot-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build_before_run": bool(args.build_before_run),
        "native_channel_state_layout": bool(args.native_channel_state_layout),
        "native_memory_layout": bool(args.native_memory_layout),
        "primary_status_extra": not bool(args.no_primary_status_extra),
        "secondary_root_extra": args.secondary_root_extra,
        "secondary_root_extra_first_override": (
            args.secondary_root_extra_first_dva
        ),
        "seeded_native_pages": seeded_native_pages,
        "post_ack_crashed": post_ack_crashed,
        "post_control_start_crashed": post_control_start_crashed,
        "prestage_backend_group": bool(args.prestage_backend_group),
        "context": args.context,
        "stage_control_instances": stage_count,
        "control_start_instances": len(control_start_indices),
        "control_start_offset": args.control_start_offset,
        "control_start_order": control_start_indices,
        "control_start_gap_ms": args.control_start_gap_ms,
        "opening_control_counters": {
            name: list(values)
            for name, values in opening_control_counters.items()
        },
        "deferred_control": deferred_control,
        "mirror_context_zero": bool(args.mirror_context_zero),
        "kern_va_base": kern_va_base,
        "handoff_base": handoff_base,
        "handoff_words": handoff_words,
        "upper_root": upper_root,
        "firmware_root": firmware_root,
        "firmware_root_writable": writable,
        "upper_root_entries": entries,
        "selectors": selectors,
        "host_walk": str(resolved),
        "handoff_protocol": bool(args.handoff),
        "preserve_shared_root": bool(args.preserve_shared_root),
        "coproc_maint_pages": coproc_maint_pages,
        "shared_root_nonzero_before": shared_root_nonzero_before,
        "context_pairs_before": context_pairs_before,
        "root_va": root_va,
        "allocations": arena.entries,
        "addr_array": addr_array,
        "region_triples": [a for a, _ in region_triples],
        "register_windows": len(register_entries),
        "acknowledged": bool(acked),
        "events": asc.fw.events,
        "control": control_result,
    }, indent=2, sort_keys=True) + "\n")
    return 0 if acked else 1


if __name__ == "__main__":
    sys.exit(main())
