#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit one generated add3 as the first CL_2 work on G17P.

This is deliberately a single-path experiment. It accepts no options, copies
no captured bytes, publishes one compute group, and treats only the caller's
physical output changing to the exact expected values as execution.

The older native-lifecycle reconstruction is frozen in
``agx_g17p_compute_lifecycle_archive.py``.
"""

import ctypes
import json
import math
import os
import pathlib
import signal
import struct
import sys
import tempfile
import time
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# Fixed experiment configuration. The public invocation has no flags or
# environment variables, and this file always owns only the Neo.
os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_RUNTIME_PAIR_GROWTH"] = "0"
os.environ["G17P_RUNTIME_LOW_ROOT_GROWTH"] = "0"
os.environ["G17P_RUNTIME_EMPTY_OPERAND_TABLE"] = "1"

from m1n1.agx import g17p, g17p_compute as compute  # noqa: E402
from m1n1.agx.g17p_backend import (                  # noqa: E402
    G17PQueue,
    G17PQueueFence,
)
from m1n1.agx.g17p_shim import (                       # noqa: E402
    grid_index_for,
    work_doorbell_channel,
)
from m1n1.agx.shim import DRMAsahiShim               # noqa: E402
from m1n1.hw.uat import MemoryAttr, TTBR              # noqa: E402

from agx_g17p_shim_submit import packed_cmdbuf        # noqa: E402


PAGE = 0x4000
EVENT_RECORD_SIZE = 0x40
PROBE_TIMEOUT = 10.0
COMPLETION_TIMEOUT = 0.010

# The exact output-positive native CL_2 publication paired with the complete
# pre-kick address-space snapshot below. These are placements in firmware-owned
# arrays; every byte stored there is generated below.
GRID = 10
QUEUE = 0xFFFFFC20C0000780
QUEUE_POINTERS = 0xFFFFFC20016FA870
ITEM_RING = 0xFFFFFC20C098A870
DESCRIPTOR = 0xFFFFFC20C0358000
DESCRIPTOR_LOW = 0x7000340000
OPTIONAL = 0xFFFFFC20C060A2C0
EVENT = 0xFFFFFC20C05ECC80
QUEUE_CONTEXT_LOW = 0x70005C8000
QUEUE_CONTEXT_HIGH = 0xFFFFFC2000368000
SCHEDULER_PAGE = 0xFFFFFC20C0998000
SCHEDULER = SCHEDULER_PAGE + 0x100
JOB_LIST = 0xFFFFFC2000000060
SHARED_SUPPORT = 0xFFFFFC20C09A0000
SHARED_STATE = 0xFFFFFC2001708000
SCHEDULER_SLOT = SHARED_STATE + 4
SUPPORT_STATE = 0xFFFFFC2001710000
ZERO_PAGE = 0xFFFFFC2001718000
DISPATCH_A = 0xFFFFFC20001C8028
DISPATCH_B = 0xFFFFFC20C07C0028
STATUS_A = 0xFFFFFC2000024C78
STATUS_B = 0xFFFFFC2000024C80
CHANNEL_CONTROL = 0xFFFFFC20C07B8100

SUBMIT_SEQUENCE = 0
SUBMISSION_ORDINAL = 0x66
QUEUE_UUID = 0x172
DISPATCH_IDENTITY = 0x020003BC030003E7
REGISTER_LIFECYCLE = 0x300
SUPPORT_WORD_10 = 2
SHARED_SUPPORT_HEADER = 3
QUEUE_CONTEXT_WORD_350 = 0x000110038001A002
QUEUE_CONTEXT_WORD_358 = 0x000020038001A03B
STATUS_A_VALUE = 0
STATUS_B_VALUE = 0

# Scalar identity from the output-positive final-26.6 CL_2 publication in
# live_submission_targeted_20260810_120637.  Addresses remain allocator-owned
# by this experiment; this profile changes only fields which identify the
# queue/submission or select its current compute context.
OUTPUT_POSITIVE_FINAL_26_6_PROFILE = {
    "grid_index": 6,
    "queue_uuid": 0x1AA,
    "dispatch_identity": 0x0200026C0300028E,
    "register_gate": 1,
    "submission_ordinal": 0x38,
    "optional_field_46": 1,
    "optional_field_56": 3,
    "shared_support_word_08": 1,
    "queue_context_word_220": 0xFFFF080300000001,
}

# Beta-4 per-channel TA/3D publication counts and outer schedule.  Final 26.6
# no longer uses this alternating-pair topology; retain it only for offline
# comparison with the historical captures.
NATIVE_RENDER_COUNTS_BY_TICK = (
    2, 3, 4, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
)
NATIVE_PRIMARY_OUTER_SCHEDULE = (
    (2, 0, 3, 1, 1, 3),
    (3, 1, 4, 2, 1, 3),
    (4, 2, 4, 2, 0, 3),
    (5, 2, 4, 2, 1, 2),
    (6, 0, 6, 2, 2, 3),
    (7, 1, 7, 4, 2, 3),
    (8, 1, 9, 6, 3, 3),
    (9, 1, 9, 6, 4, 2),
    (10, 1, 11, 8, 5, 3),
    (11, 1, 13, 10, 6, 3),
    (12, 1, 15, 12, 7, 3),
    (13, 1, 17, 14, 8, 3),
    (14, 1, 19, 16, 9, 3),
    (15, 1, 21, 18, 10, 3),
    (16, 1, 23, 20, 11, 3),
    (17, 1, 25, 22, 12, 3),
    (18, 1, 27, 24, 13, 3),
    (19, 1, 29, 26, 14, 3),
    (20, 1, 31, 28, 15, 3),
    (21, 1, 33, 30, 16, 3),
    (22, 1, 35, 32, 17, 3),
    (23, 1, 37, 34, 18, 3),
    (24, 1, 39, 0, 19, 3),
    (25, 1, 41, 2, 20, 3),
    (26, 1, 43, 4, 21, 3),
    (27, 1, 45, 6, 22, 3),
    (28, 1, 47, 8, 23, 3),
    (29, 1, 49, 10, 24, 3),
    (30, 1, 51, 12, 25, 3),
    (31, 1, 53, 14, 26, 3),
)

# Final 26.6 keeps the opening pair-zero queues and appends one normal
# three-item TA/3D group after each sequenced 0x2e.  The captured prefix reaches
# 32 physical-output-positive renders and control sequence 30.
FINAL_26_6_RENDER_PREFIX_COUNT = 32

PRIMARY_PAIR2_PRIMARY = 0xFFFFFC20C08D0000
PRIMARY_PAIR2_SECONDARY = 0xFFFFFC20C08C0000
PRIMARY_PAIR2_SHARED_SLOTS = 0xFFFFFC2001670000
PRIMARY_PAIR2_FLAG = 0xFFFFFC2001678000
PRIMARY_PAIR2_POOL_A = 0xFFFFFC20C0820100
PRIMARY_PAIR2_POOL_A_SLOTS = 0xFFFFFC20015F8000
PRIMARY_PAIR2_POOL_B = 0xFFFFFC20C08B8080
PRIMARY_PAIR2_POOL_B_SLOTS = 0xFFFFFC2001620000
PRIMARY_PAIR2_SHARED = 0xFFFFFC20C08E8000
PRIMARY_PAIR2_ZERO = 0xFFFFFC20C08BA800

# Fresh caller-owned client objects. Context 3 is pointed at their generated
# roots before submission; payload addresses and contents are ours.
SHADER = 0x10004000000
RESOURCE = 0x10004040000
RESOURCE_SIZE = 0xC000
CDM = 0x10004100000
BUFFER_A = 0x10004200000
BUFFER_B = 0x10004204000
BUFFER_OUT = 0x10004208000
ROBUSTNESS = 0x10004300000
# Exact context-3 low-side layout at the successful native pre-CL2 boundary.
# Cold boot already constructs the containing low client extent; compute owns
# these subranges and initializes their contents before publication.
CLIENT_STATE = 0x7000208000
CLIENT_STATE_ZERO = CLIENT_STATE + 0x18000
CONTROL_OPERAND = 0x70017C0000
PRIMARY_CONTROL_OPERAND = 0x7000208000
ACTIVATION_CONTROL_OPERAND = 0x7002108000
ACTIVATION_LOW_BUFFER = 0x7001F00000
SCRATCH = CLIENT_STATE + 0x20000
OPERAND_BUFFER_BASE = CLIENT_STATE + 0x30000
OPERAND_PAGE_LIST_BASE = 0x7000000000
OPERAND_PAGE_LIST_REGION_SIZE = 0x200000
OPERAND_TABLE_REGION_SIZE = 0x10000
CLIENT_STATE_REGION_SIZE = 0x14000
RENDER_WITNESS = 0x20002000000
RENDER_DEPENDENCY_ALIAS = 0x10008000000

# Final 26.6 repurposes queue-pair resource pages as compact control objects.
# The class-1 object/state are pair 1's secondary-index and flag pages; the
# class-3 object/state are pair 0's completed primary-index page and pair 1's
# fragment-status page.  These identities are part of the transition, not
# arbitrary storage for otherwise equivalent bytes.
FINAL_26_6_CLASS1_SUPPORT = 0xFFFFFC20C0878000
FINAL_26_6_CLASS1_STATE = 0xFFFFFC2001648000
FINAL_26_6_CLASS3_SUPPORT = 0xFFFFFC20C0850000
FINAL_26_6_CLASS3_STATE = 0xFFFFFC2001650000

# One-time output-positive client-state control.  Both inputs are hardware
# observations of the clean-room t9probe workload: the full snapshot supplies
# its pre-kick context-3 pages, while the smaller targeted capture supplies the
# exact descriptor and the physically changed post-kick output page.
NATIVE_CLIENT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_t256_write_full_20260806_085603"
)
NATIVE_ITEM_CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260806_085451/CL_2"
)
NATIVE_SHADER = 0x100000D8000
NATIVE_RESOURCE = 0x10000128000
NATIVE_CDM = 0x100000F8000
NATIVE_OUTPUT = 0x1000018000

PRIMARY_RECORD_A_HIGH = 0xFFFFFC20015E0000
PRIMARY_RECORD_A_LOW = 0x7001838000
PRIMARY_RECORD_B_HIGH = 0xFFFFFC20015E8000
PRIMARY_RECORD_B_LOW = 0x7001840000
PRIMARY_RECORD_PREDECESSOR = 0xFFFFFC20015D8000
PRIMARY_RECORD_SENTINEL = 0xFFFFFC20C07C8000

# Compact control-support graphs named by the final same-stop device-control
# suffix before CL_2.  The class-1 and class-2 objects use the same 0x70-byte
# packed format but own independent low page-list/table regions and firmware
# state pages.
NATIVE_CLASS1_SUPPORT = 0xFFFFFC20C0908000
NATIVE_CLASS1_STATE = 0xFFFFFC20016A8000
NATIVE_CLASS1_PAGE_LIST = 0x7001090000
NATIVE_CLASS1_OPERAND = 0x7001298000
NATIVE_CLASS1_LOW_EXTENTS = (
    (NATIVE_CLASS1_PAGE_LIST + 0x000000, 0x010000),
    (NATIVE_CLASS1_PAGE_LIST + 0x018000, 0x100000),
    (NATIVE_CLASS1_PAGE_LIST + 0x120000, 0x0F8000),
)
NATIVE_CLASS1_LOW_SPAN = 0x218000
NATIVE_CLASS2_SUPPORT = 0xFFFFFC20C0950000
NATIVE_CLASS2_STATE = 0xFFFFFC20016D8000
NATIVE_CLASS2_PAGE_LIST = OPERAND_PAGE_LIST_BASE
NATIVE_CLASS2_OPERAND = CLIENT_STATE
NATIVE_CLASS2_PAGE_LIST_SIZE = 0x200000
NATIVE_CONTROL_OPERAND_SIZE = 0x10000

# Complete nonzero predecessor-page fields at the same native pre-kick
# boundary.  The adjacent sentinel page is mapped but entirely blank.
NATIVE_COMPUTE_PREDECESSOR_U32 = (
    *((offset, 0xFF) for offset in range(0x00, 0x50, 0x08)),
    (0x050, 0x00000404),
    (0x400, 0x00000006), (0x404, 0x00000006),
    (0x408, 0x0000006E), (0x40C, 0x0000006E),
    (0x410, 0x00000014), (0x414, 0x00000014),
    (0x418, 0x00000003), (0x41C, 0x00000003),
    (0x420, 0x0000000E), (0x424, 0x0000000E),
    (0x428, 0x00000001),
    (0x600, 0x0000000C), (0x604, 0x000000F8),
    (0x608, 0x00000028), (0x60C, 0x00000006),
    (0x610, 0x00000001),
    (0xC00, 0x00002000), (0xC04, 0x00002000),
    (0xC08, 0x00002000), (0xC0C, 0x00002000),
    (0xC10, 0x00002000),
)
NATIVE_COMPUTE_PREDECESSOR_U64 = (
    (0x800, 0xFFFFFC20C07B8040),
    (0x808, 0xFFFFFC20C07B8000),
    (0x810, 0xFFFFFC20C07B8080),
    (0x818, 0xFFFFFC20C07B80C0),
    (0x820, 0xFFFFFC20C07B8100),
    (0xE00, 0x00000000000000D5),
    (0xE08, 0x0000000107A7434E),
    (0xE10, 0x0000000107A73B9B),
    (0xE18, 0x0000000107CE37B9),
    (0xE20, 0x0000000000000099),
    (0xE28, 0x0000000000000099),
    (0xE30, 0x0000000000000001),
)

# Complete host-visible record sets immediately before the output-positive
# native CL_2 kick.  These are structured fields, not copied page contents.
NATIVE_COMPUTE_RECORDS_A = (
    (0x00019000, 0x000000A0, 0x0000000C, 0x0000000C),
    (0x00077000, 0x000000A0, 0x0000004B, 0x0000004B),
    (0x00019000, 0x00000020, 0x00000008, 0x00000008),
    (0x00034000, 0x00000020, 0x00000008, 0x00000008),
    (0x0010E000, 0x000000A0, 0x00000088, 0x00000088),
)
NATIVE_COMPUTE_RECORDS_B = (
    (0xE0021200, 0x08000000, 0x00030400, 0x00006A40, 0x00001D00),
    (0xE0000000, 0x08000000, 0x00005E00, 0x000039E0, 0x00001A00),
    (0xE0000000, 0x08000000, 0x00000000, 0x00002A00, 0x00001500),
    (0xE0040300, 0x08000000, 0x00000000, 0x00002600, 0x00001300),
)

# The same complete region at the output-positive final-26.6 boundary.  The
# topology is unchanged, but these live scheduler/resource records reflect the
# later workload history.  Keep them separate from the Aug-6 values so a test
# cannot accidentally combine two internally coherent boundaries.
FINAL_26_6_COMPUTE_PREDECESSOR_U32 = (
    *((offset, 0xFF) for offset in range(0x00, 0x50, 0x08)),
    (0x050, 0x00000404),
    (0x400, 0x00000004), (0x404, 0x00000004),
    (0x408, 0x00000039), (0x40C, 0x00000039),
    (0x410, 0x00000002), (0x414, 0x00000002),
    (0x418, 0x00000014), (0x41C, 0x00000014),
    (0x420, 0x00000003), (0x424, 0x00000003),
    (0x428, 0x00000001),
    (0x600, 0x00000008), (0x604, 0x00000076),
    (0x608, 0x00000028), (0x60C, 0x00000006),
    (0x610, 0x00000001),
    (0xC00, 0x00002000), (0xC04, 0x00002000),
    (0xC08, 0x00002000), (0xC0C, 0x00002000),
    (0xC10, 0x00002000),
)
FINAL_26_6_COMPUTE_PREDECESSOR_U64 = (
    (0x800, 0xFFFFFC20C07B8040),
    (0x808, 0xFFFFFC20C07B8000),
    (0x810, 0xFFFFFC20C07B8080),
    (0x818, 0xFFFFFC20C07B80C0),
    (0x820, 0xFFFFFC20C07B8100),
    (0xE00, 0x0000000000000089),
    (0xE08, 0x0000000142147319),
    (0xE10, 0x0000000142144B8A),
    (0xE18, 0x00000001423DF4C5),
    (0xE20, 0x0000000000000056),
    (0xE28, 0x0000000000000056),
    (0xE30, 0x0000000000000001),
)
FINAL_26_6_COMPUTE_RECORDS_A = (
    (0x00019000, 0x000000A0, 0x00000004, 0x00000004),
    (0x00076800, 0x00000080, 0x00000046, 0x00000046),
    (0x000D4000, 0x00000080, 0x0000001E, 0x0000001E),
    (0x00019000, 0x00000020, 0x0000000A, 0x0000000A),
    (0x00033800, 0x00000020, 0x0000000C, 0x0000000C),
)
FINAL_26_6_COMPUTE_RECORDS_B = (
    (0xE003E000, 0x08000000, 0x0003BC00, 0x000073C0, 0x00001C00),
    (0xE0018E00, 0x08000000, 0x00031E00, 0x00005DE0, 0x00001600),
    (0xE0000000, 0x08000000, 0x00000000, 0x00002A00, 0x00001500),
)

# Clean-room add3 shader from EXP-0011, including its verified constant footer.
ADD3_SHADER = bytes.fromhex(
    "2ca00200120870003c80020004000000"
    "8ca0420000000c009c80420004000000"
    "6700542c020000005900024026006700"
    "54240200000057000040260067005430"
    "1800000059040040260077002a410000"
    "00007701aa07000000020400f7002a00"
    "0000000000001c800200000000001481"
    "1106000000000c800200040000009f11"
    "5400020008a810051c80020004000000"
    "0f1254004c004b2c09445b2e09040b24"
    "09041b2609042b2809043b2a09046b30"
    "09047b32090403000700020000006000"
    "0e000000"
)


class ProbeTimeout(TimeoutError):
    pass


def _timeout(_signum, _frame):
    raise ProbeTimeout("compute probe exceeded 10 seconds")


def map_client(
        backend, address, size, name, read_only=False, reuse=False,
        space=None):
    space = backend.space if space is None else space
    translated = space.uat.iotranslate(space.context, address, size)
    if any(pa is not None for pa, _length in translated):
        covered = sum(length for pa, length in translated if pa is not None)
        if reuse and all(pa is not None for pa, _length in translated) and covered >= size:
            return address, translated[0][0]
        end = address + size
        owners = []
        for obj in space.objects:
            obj_address = int(obj.get("map_va", obj["va"]))
            obj_size = int(obj.get("map_size", obj["size"]))
            if address < obj_address + obj_size and obj_address < end:
                owners.append("%s@%#x+%#x" % (
                    obj["name"], obj_address, obj_size))
        raise RuntimeError(
            "%s DVA %#x is already mapped to PA %#x (%s)" % (
                name, address,
                next(pa for pa, _length in translated if pa is not None),
                ", ".join(owners) if owners else "untracked mapping"))
    return space.alloc_at(
        address, size, name, AttrIndex=MemoryAttr.Shared,
        AP=2, nG=1, UXN=0 if read_only else 1, OS=1,
    )


def create_compute_context3_space(backend):
    """Create the independent low root selected by native CL2 descriptors."""
    space = type(backend.space)(backend.u, 3, SHADER)
    space.use_absent_handoff()
    root = space.uat.ttbr0_base
    backend.u.proxy.memset32(root, 0, PAGE)
    backend.u.proxy.dc_civac(root, PAGE)
    space.uat.ttbr1_base = (
        getattr(backend, "firmware_high_root", None)
        or backend.space.uat.ttbr1_base)
    space.uat.initialized = True
    space.uat.set_l0(3, 0, root, 3)
    space.uat.set_l0(3, 1, space.uat.ttbr1_base, 3)
    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 3 << 48)
    backend.u.inst("dsb sy")
    print(
        "COMPUTE created independent context-3 low root %#x, high root %#x" %
        (root, space.uat.ttbr1_base),
        flush=True,
    )
    return space


def map_firmware(backend, address, size):
    backend._ensure_firmware_range(address, size)


def alias_firmware(backend, high, low, size):
    map_firmware(backend, high, size)
    root = backend.firmware_high_root
    high_page = high & ~(PAGE - 1)
    low_page = low & ~(PAGE - 1)
    end = (high + size + PAGE - 1) & ~(PAGE - 1)
    for page in range(high_page, end, PAGE):
        translated = backend.space.uat.iotranslate_root(root, page, PAGE)
        if not translated or translated[0][0] is None:
            raise RuntimeError("firmware alias source %#x is unmapped" % page)
        backend.space.uat.iomap_at(
            0, low_page + page - high_page, translated[0][0], PAGE,
            AttrIndex=MemoryAttr.Shared, AP=2, nG=1, UXN=0, OS=1,
        )


def physical_read(backend, pa, size):
    backend.u.proxy.dc_ivac(pa, size)
    return bytes(backend.u.iface.readmem(pa, size))


def install_native_compute_primary_records(backend):
    """Publish and verify the complete native primary pre-compute region."""
    final_26_6 = os.getenv("G17P_COMPUTE_FINAL_26_6_PRIMARY_RECORDS") == "1"
    predecessor_u32 = (
        FINAL_26_6_COMPUTE_PREDECESSOR_U32
        if final_26_6 else NATIVE_COMPUTE_PREDECESSOR_U32)
    predecessor_u64 = (
        FINAL_26_6_COMPUTE_PREDECESSOR_U64
        if final_26_6 else NATIVE_COMPUTE_PREDECESSOR_U64)
    records_a = (
        FINAL_26_6_COMPUTE_RECORDS_A
        if final_26_6 else NATIVE_COMPUTE_RECORDS_A)
    records_b = (
        FINAL_26_6_COMPUTE_RECORDS_B
        if final_26_6 else NATIVE_COMPUTE_RECORDS_B)
    predecessor = bytearray(PAGE)
    for offset, value in predecessor_u32:
        struct.pack_into("<I", predecessor, offset, value)
    for offset, value in predecessor_u64:
        struct.pack_into("<Q", predecessor, offset, value)

    page_a = bytearray(PAGE)
    for index, record in enumerate(records_a):
        struct.pack_into("<4I", page_a, index * 0x10, *record)
    page_b = bytearray(PAGE)
    for index, record in enumerate(records_b):
        struct.pack_into("<5I", page_b, index * 0x20, *record)

    print(
        "COMPUTE primary record profile: %s" %
        ("output-positive final-26.6" if final_26_6 else "Aug-6 t256"),
        flush=True,
    )

    # The predecessor and sentinel have no context-0 aliases.  Make both
    # explicit and verify them before checking the two aliased record pages.
    for high, body in (
            (PRIMARY_RECORD_PREDECESSOR, bytes(predecessor)),
            (PRIMARY_RECORD_SENTINEL, bytes(PAGE))):
        high_ranges = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, high, PAGE)
        if not high_ranges or high_ranges[0][0] is None:
            raise RuntimeError(
                "primary scheduler region %#x is unmapped" % high)
        backend._write_dva(high, body)
        backend._clean_dva_range(high, PAGE)
        backend.u.inst("dsb sy")
        high_read = backend.space.uat.ioread_root(
            backend.firmware_high_root, high, PAGE)
        if high_read != body:
            raise RuntimeError(
                "primary scheduler region readback mismatch at %#x" % high)
        print(
            "COMPUTE primary region %#x PA %#x verified" %
            (high, high_ranges[0][0]),
            flush=True,
        )

    for high, low, body in (
            (PRIMARY_RECORD_A_HIGH, PRIMARY_RECORD_A_LOW, bytes(page_a)),
            (PRIMARY_RECORD_B_HIGH, PRIMARY_RECORD_B_LOW, bytes(page_b))):
        high_ranges = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, high, PAGE)
        low_ranges = backend.space.uat.iotranslate(0, low, PAGE)
        if not high_ranges or not low_ranges:
            raise RuntimeError("primary scheduler record alias is unmapped")
        high_pa = high_ranges[0][0]
        low_pa = low_ranges[0][0]
        if high_pa is None or low_pa is None or high_pa != low_pa:
            raise RuntimeError(
                "primary scheduler record is not aliased: high %#x -> %r, "
                "low %#x -> %r" % (high, high_pa, low, low_pa))
        backend._write_dva(high, body)
        backend._clean_dva_range(high, PAGE)
        backend.u.inst("dsb sy")
        high_read = backend.space.uat.ioread_root(
            backend.firmware_high_root, high, PAGE)
        low_read = backend.space.uat.ioread(0, low, PAGE)
        if high_read != body or low_read != body:
            raise RuntimeError(
                "primary scheduler record alias readback mismatch at %#x/%#x" %
                (high, low))
        print(
            "COMPUTE primary records %#x/%#x alias PA %#x verified" %
            (high, low, high_pa),
            flush=True,
        )


def prepare_native_pre_cl2_control_objects(backend, client_space):
    """Map the complete native compact-control closure without publishing it."""
    for address in (
            NATIVE_CLASS1_SUPPORT, NATIVE_CLASS1_STATE,
            NATIVE_CLASS2_SUPPORT, NATIVE_CLASS2_STATE):
        map_firmware(backend, address, PAGE)

    class1_extents = []
    for index, (address, size) in enumerate(NATIVE_CLASS1_LOW_EXTENTS):
        class1_extents.append(map_client(
            backend, address, size,
            "native_class1_low_extent_%d" % index,
            reuse=True, space=client_space))
    class1_operand = map_client(
        backend, NATIVE_CLASS1_OPERAND, NATIVE_CONTROL_OPERAND_SIZE,
        "native_class1_operand", reuse=True, space=client_space)
    # The class-2 graph aliases the compute graph already constructed from
    # the same capture: three populated page-list pages inside a 2 MiB mapping
    # and the 21-entry operand table at +0x208000.
    map_client(
        backend, NATIVE_CLASS2_PAGE_LIST, NATIVE_CLASS2_PAGE_LIST_SIZE,
        "native_class2_page_lists", reuse=True, space=client_space)
    map_client(
        backend, NATIVE_CLASS2_OPERAND, NATIVE_CONTROL_OPERAND_SIZE,
        "native_class2_operand", reuse=True, space=client_space)

    for (_address, size), (_dva, pa) in zip(
            NATIVE_CLASS1_LOW_EXTENTS, class1_extents):
        backend.u.proxy.memset32(pa, 0, size)
        backend.u.proxy.dc_civac(pa, size)

    client_space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 3 << 48)
    backend.u.inst("dsb sy")
    return {
        "class1_extents": class1_extents,
        "class1_operand": class1_operand,
    }


def build_native_pre_cl2_control_objects():
    """Return the two exact retired compact objects and state pages."""
    class1 = compute.build_compute_class1_support(
        NATIVE_CLASS1_OPERAND, NATIVE_CLASS1_PAGE_LIST,
        NATIVE_CLASS1_STATE,
        active=0, cursor=0xE8, final_kind=2,
        word_20=0x0000352000001820,
        word_28=0x00001D0000000000,
        field_54=0x4E,
    )
    class2 = compute.build_compute_class2_support(
        NATIVE_CLASS2_OPERAND, NATIVE_CLASS2_PAGE_LIST,
        NATIVE_CLASS2_STATE,
        active=1, cursor=0xD0, final_kind=3,
        word_20=0x00001CF0000002F0,
        word_28=0x00001A0000000000,
        field_54=0x0C,
    )
    state1 = bytearray(PAGE)
    state2 = bytearray(PAGE)
    struct.pack_into("<Q", state1, 0, 0x4E)
    struct.pack_into("<Q", state2, 0, 0x0C)
    return {
        "class1": class1,
        "class1_state": bytes(state1),
        "class2": class2,
        "class2_state": bytes(state2),
    }


def install_native_pre_cl2_control_objects(backend, client_space):
    """Construct the two retired compact graphs at the same-stop boundary."""
    prepare_native_pre_cl2_control_objects(backend, client_space)
    objects = build_native_pre_cl2_control_objects()
    for address, body in (
            (NATIVE_CLASS1_SUPPORT, objects["class1"]),
            (NATIVE_CLASS1_STATE, objects["class1_state"]),
            (NATIVE_CLASS2_SUPPORT, objects["class2"]),
            (NATIVE_CLASS2_STATE, objects["class2_state"])):
        backend._write_dva(address, body)
        backend._clean_dva_range(address, PAGE)
    backend.u.inst("dsb sy")

    for label, address, expected in (
            ("class1 support", NATIVE_CLASS1_SUPPORT, objects["class1"]),
            ("class1 state", NATIVE_CLASS1_STATE,
             objects["class1_state"]),
            ("class2 support", NATIVE_CLASS2_SUPPORT, objects["class2"]),
            ("class2 state", NATIVE_CLASS2_STATE,
             objects["class2_state"])):
        actual = coherent_dva_read(backend, address, PAGE)
        if actual != expected:
            raise RuntimeError(
                "native pre-CL2 %s readback mismatch at %#x" %
                (label, address))
    print(
        "COMPUTE constructed exact same-stop class1/class2 support graphs",
        flush=True,
    )
    return objects


def install_final_26_6_control_objects(backend):
    """Construct the compact class-1/class-3 objects seen before native CL2."""
    for address in (
            FINAL_26_6_CLASS1_SUPPORT, FINAL_26_6_CLASS1_STATE,
            FINAL_26_6_CLASS3_SUPPORT, FINAL_26_6_CLASS3_STATE):
        map_firmware(backend, address, PAGE)

    class1 = compute.build_compute_compact_control_support(
        1, PRIMARY_CONTROL_OPERAND, 0, FINAL_26_6_CLASS1_STATE,
        active=1, resource_class=0x11, cursor=0x88, final_kind=2,
    )
    class3 = compute.build_compute_compact_control_support(
        3, PRIMARY_CONTROL_OPERAND, 0, FINAL_26_6_CLASS3_STATE,
        active=2, resource_class=0x17, cursor=0xB8, final_kind=3,
    )
    state = bytearray(PAGE)
    struct.pack_into("<I", state, 0, 1)
    objects = {
        "class1": class1 + bytes(PAGE - len(class1)),
        "class1_state": bytes(state),
        "class3": class3 + bytes(PAGE - len(class3)),
        "class3_state": bytes(state),
    }
    for address, body in (
            (FINAL_26_6_CLASS1_SUPPORT, objects["class1"]),
            (FINAL_26_6_CLASS1_STATE, objects["class1_state"]),
            (FINAL_26_6_CLASS3_SUPPORT, objects["class3"]),
            (FINAL_26_6_CLASS3_STATE, objects["class3_state"])):
        backend._write_dva(address, body)
        backend._clean_dva_range(address, PAGE)
    backend.u.inst("dsb sy")

    for label, address, expected in (
            ("class1 support", FINAL_26_6_CLASS1_SUPPORT, objects["class1"]),
            ("class1 state", FINAL_26_6_CLASS1_STATE,
             objects["class1_state"]),
            ("class3 support", FINAL_26_6_CLASS3_SUPPORT, objects["class3"]),
            ("class3 state", FINAL_26_6_CLASS3_STATE,
             objects["class3_state"])):
        if coherent_dva_read(backend, address, PAGE) != expected:
            raise RuntimeError(
                "final-26.6 %s readback mismatch at %#x" % (label, address))
    print(
        "COMPUTE constructed final-26.6 class1/class3 control objects",
        flush=True,
    )
    return objects


def _targeted_capture_bytes(address, size):
    manifest = json.loads((NATIVE_ITEM_CAPTURE / "pages.json").read_text())
    raw = (NATIVE_ITEM_CAPTURE / "pages.bin").read_bytes()
    pages = {
        int(record["dva"]): raw[
            int(record["capture_offset"]):
            int(record["capture_offset"]) + PAGE
        ]
        for record in manifest["pages"]
    }
    body = bytearray()
    cursor = int(address)
    remaining = int(size)
    while remaining:
        page = cursor & ~(PAGE - 1)
        if page not in pages:
            raise RuntimeError(
                "targeted capture has no page for DVA %#x" % cursor)
        offset = cursor - page
        take = min(remaining, PAGE - offset)
        body.extend(pages[page][offset:offset + take])
        cursor += take
        remaining -= take
    return bytes(body)


def native_compute_descriptor():
    """Return the exact output-positive t9probe descriptor observation."""
    return _targeted_capture_bytes(DESCRIPTOR, compute.COMPUTE_DESCRIPTOR_SIZE)


def _build_exact_native_low_root(backend, manifest, group, leaf_pas):
    """Rebase one captured, fully closed UAT hierarchy onto current leaf PAs."""
    table_records = {
        int(record["original_pa"]): int(record["index"])
        for record in manifest["table_page_records"]
    }
    original_tables = [int(pa) for pa in group["table_pages"]]
    missing = [pa for pa in original_tables if pa not in table_records]
    if missing:
        raise RuntimeError(
            "native UAT capture omits table pages: %s" %
            ", ".join("%#x" % pa for pa in missing))
    if group.get("unsupported_entries"):
        raise RuntimeError("native UAT hierarchy contains unsupported entries")

    raw = (NATIVE_CLIENT_SNAPSHOT / manifest["tables_file"]).read_bytes()
    base_pa = backend.u.memalign(PAGE, len(original_tables) * PAGE)
    table_pas = {
        original: base_pa + index * PAGE
        for index, original in enumerate(original_tables)
    }
    offset_mask = ((1 << 48) - 1) & ~(PAGE - 1)
    payload = bytearray()
    patched_tables = patched_leaves = 0
    for original in original_tables:
        index = table_records[original]
        body = bytearray(raw[index * PAGE:(index + 1) * PAGE])
        if len(body) != PAGE:
            raise RuntimeError("native UAT table payload is truncated")
        for offset in range(0, PAGE, 8):
            value = struct.unpack_from("<Q", body, offset)[0]
            if not value & 1:
                continue
            target = value & offset_mask
            replacement = table_pas.get(target)
            if replacement is not None:
                patched_tables += 1
            else:
                replacement = leaf_pas.get(target)
                if replacement is None:
                    raise RuntimeError(
                        "native UAT entry at %#x+%#x names unknown PA %#x" %
                        (original, offset, target))
                patched_leaves += 1
            struct.pack_into(
                "<Q", body, offset,
                (value & ~offset_mask) | (replacement & offset_mask),
            )
        payload.extend(body)

    backend.u.iface.writemem(base_pa, payload)
    backend.u.proxy.dc_civac(base_pa, len(payload))
    root = table_pas[int(group["root_pa"])]
    print(
        "COMPUTE rebuilt exact native UAT hierarchy at root %#x: "
        "%d tables, %d table links, %d leaves" %
        (root, len(original_tables), patched_tables, patched_leaves),
        flush=True,
    )
    return root


def install_native_client_context(backend):
    """Install the reachable captured pre-kick context-3 client address space.

    The descriptor's registered 0x700... operand pages already exist as live,
    generated lifecycle state and are inherited by the cloned root.  Rewinding
    their captured contents would both waste most of the transfer and destroy
    the state just admitted by the control protocol.  All other descriptor
    targets are closed over qword pointers and complete contiguous mapping runs.
    This is still deliberately broad client-state replay, but replaces no
    firmware-owned page or lifecycle state.
    """
    manifest = json.loads((NATIVE_CLIENT_SNAPSHOT / "manifest.json").read_text())
    groups = [
        group for group in manifest["root_mappings"]
        if int(group.get("root_ctx_id", -1)) == 3
        and int(group.get("selector", -1)) == 0
    ]
    if len(groups) != 1:
        raise RuntimeError(
            "native snapshot has %d context-3 low roots, expected one" %
            len(groups))
    hardware_slot = int(groups[0]["root_index"])
    all_mappings = [
        mapping for mapping in groups[0]["mappings"]
        if mapping.get("blob_index") is not None
    ]
    if not all_mappings:
        raise RuntimeError("native context-3 root contains no captured pages")

    ram = (NATIVE_CLIENT_SNAPSHOT / manifest["ram_file"]).read_bytes()
    by_address = {
        int(mapping["va"]): mapping for mapping in all_mappings
    }

    def page_body(address):
        mapping = by_address[address]
        index = int(mapping["blob_index"])
        return ram[index * PAGE:(index + 1) * PAGE]

    full_context = os.getenv("G17P_COMPUTE_NATIVE_FULL_CONTEXT") == "1"

    def replayable(address):
        # These are the generated, live operand table and buffer namespace.
        return full_context or not 0x7000000000 <= address < 0x8000000000

    addresses = sorted(by_address)
    runs = []
    start = previous = addresses[0]
    for address in addresses[1:]:
        if address != previous + PAGE:
            runs.append(tuple(range(start, previous + PAGE, PAGE)))
            start = address
        previous = address
    runs.append(tuple(range(start, previous + PAGE, PAGE)))
    run_for = {
        address: run for run in runs for address in run
    }

    descriptor = native_compute_descriptor()
    inherited = set()
    if full_context:
        selected = set(by_address)
    else:
        seeds = {NATIVE_SHADER & ~(PAGE - 1)}
        for index in range(compute.COMPUTE_REGISTER_CAPACITY):
            number, value = struct.unpack_from(
                "<IQ", descriptor,
                compute.COMPUTE_REGISTER_START +
                index * compute.COMPUTE_REGISTER_SIZE,
            )
            if number == 0 and value == 0:
                break
            for candidate in (value, value & ((1 << 48) - 1)):
                page = candidate & ~(PAGE - 1)
                if page not in by_address:
                    continue
                if replayable(page):
                    seeds.add(page)
                else:
                    inherited.add(page)

        selected = set(seeds)
        scanned = set()
        while True:
            for address in tuple(selected):
                selected.update(
                    page for page in run_for[address] if replayable(page))
            pending = selected - scanned
            if not pending:
                break
            for address in pending:
                body = page_body(address)
                for offset in range(0, PAGE - 7, 4):
                    value = struct.unpack_from("<Q", body, offset)[0]
                    for candidate in (value, value & ((1 << 48) - 1)):
                        page = candidate & ~(PAGE - 1)
                        if page not in by_address:
                            continue
                        if replayable(page):
                            selected.add(page)
                        else:
                            inherited.add(page)
                scanned.add(address)

    mappings = [by_address[address] for address in sorted(selected)]
    payload = b"".join(
        ram[int(mapping["blob_index"]) * PAGE:
            (int(mapping["blob_index"]) + 1) * PAGE]
        for mapping in mappings
    )
    if len(payload) != len(mappings) * PAGE:
        raise RuntimeError("native context-3 payload is truncated")

    uat = backend.space.uat
    logical_slot_base = uat.gpu_region + 3 * 16
    displaced_roots = (
        TTBR(backend.u.proxy.read64(logical_slot_base)),
        TTBR(backend.u.proxy.read64(logical_slot_base + 8)),
    )
    state = backend.create_execution_context(3)
    space = state["space"]
    for address in sorted(inherited):
        translated = space.uat.iotranslate(3, address, 1)
        if not translated or translated[0][0] is None:
            raise RuntimeError(
                "generated lifecycle did not map inherited operand page %#x" %
                address)
    base_pa = backend.u.memalign(PAGE, len(payload))
    backend.u.iface.writemem(base_pa, payload)
    backend.u.proxy.dc_civac(base_pa, len(payload))

    output_pa = None
    native_leaf_pas = {}
    for index, mapping in enumerate(mappings):
        address = int(mapping["va"])
        pte = int(mapping["pte"])
        pa = base_pa + index * PAGE
        native_leaf_pas[int(mapping["pa"])] = pa
        flags = {
            "AttrIndex": (pte >> 2) & 7,
            "AP": (pte >> 6) & 3,
            "SH": (pte >> 8) & 3,
            "AF": (pte >> 10) & 1,
            "nG": (pte >> 11) & 1,
            "PXN": (pte >> 53) & 1,
            "UXN": (pte >> 54) & 1,
            "OS": (pte >> 55) & 1,
        }
        space.uat.iomap_at(space.context, address, pa, PAGE, **flags)
        if address == NATIVE_OUTPUT:
            output_pa = pa

    if output_pa is None:
        raise RuntimeError(
            "native context-3 root has no output page at %#x" % NATIVE_OUTPUT)
    # The descriptor's logical context ID is 3, but the native hardware root
    # table carries that ASID in slot 14.  Registering the tree in slot 3 is a
    # software convenience of create_execution_context(), not the captured
    # accelerator topology.  The native high tree is a separate empty root.
    if os.getenv("G17P_COMPUTE_NATIVE_EXACT_TABLES") == "1":
        space.uat.ttbr0_base = _build_exact_native_low_root(
            backend, manifest, groups[0], native_leaf_pas)
        space.uat.set_l0(3, 0, space.uat.ttbr0_base, 3)

    native_high_root = backend.u.memalign(PAGE, PAGE)
    backend.u.proxy.memset32(native_high_root, 0, PAGE)
    backend.u.proxy.dc_civac(native_high_root, PAGE)
    space.uat.set_l0(hardware_slot, 0, space.uat.ttbr0_base, 3)
    space.uat.set_l0(hardware_slot, 1, native_high_root, 3)
    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 3 << 48)
    backend.u.inst("dsb sy")
    resolved = space.uat.iotranslate(3, NATIVE_OUTPUT, 1)
    if not resolved or resolved[0][0] != output_pa:
        raise RuntimeError(
            "native output translation is %r, expected PA %#x" %
            (resolved, output_pa))
    native_resolved = space.uat.iotranslate(hardware_slot, NATIVE_OUTPUT, 1)
    if not native_resolved or native_resolved[0][0] != output_pa:
        raise RuntimeError(
            "native hardware slot %d output translation is %r, expected PA %#x" %
            (hardware_slot, native_resolved, output_pa))

    def restore_displaced_logical_slot():
        for selector, root in enumerate(displaced_roots):
            base = (root.BADDR << 1) if root.VALID else 0
            space.uat.set_l0(3, selector, base, root.ASID)
        space.uat.flush_dirty()
        space.uat.invalidate_cache()
        backend.u.inst("dsb sy")
        backend.u.inst("tlbi vmalle1os")
        backend.u.inst("dsb sy")
        print(
            "COMPUTE restored generated slot 3 and retained logical "
            "context 3 in native hardware slot %d" % hardware_slot,
            flush=True,
        )

    print(
        "COMPUTE installed %d %s captured client pages and retained "
        "%d live operand pages in logical context 3 / hardware slot %d; "
        "output %#x -> PA %#x" %
        (len(mappings), "complete" if full_context else "reachable",
         len(inherited), hardware_slot,
         NATIVE_OUTPUT, output_pa),
        flush=True,
    )
    return {
        "space": space,
        "output_dva": NATIVE_OUTPUT,
        "output_pa": output_pa,
        "expected_output": _targeted_capture_bytes(NATIVE_OUTPUT, PAGE),
        "descriptor": descriptor,
        "hardware_slot": hardware_slot,
        "full_context": full_context,
        "restore_displaced_logical_slot": restore_displaced_logical_slot,
    }


def install_native_firmware_high_context(backend):
    """Restore the complete captured firmware-high page image in place.

    Existing mappings keep their current physical backing so boot-owned host
    objects remain valid. Missing pages receive fresh backing. The captured
    leaf attributes and contents are then installed at every captured DVA;
    callers must rebuild any deliberately owned submission records afterward.
    """
    manifest = json.loads((NATIVE_CLIENT_SNAPSHOT / "manifest.json").read_text())
    groups = [
        group for group in manifest["root_mappings"]
        if int(group.get("root_ctx_id", -1)) == 64
        and int(group.get("selector", -1)) == 1
    ]
    if len(groups) != 1:
        raise RuntimeError(
            "native snapshot has %d firmware-high roots, expected one" %
            len(groups))
    mappings = sorted(
        (mapping for mapping in groups[0]["mappings"]
         if mapping.get("blob_index") is not None),
        key=lambda mapping: int(mapping["va"]),
    )
    if not mappings:
        raise RuntimeError("native firmware-high root contains no captured pages")

    ram = (NATIVE_CLIENT_SNAPSHOT / manifest["ram_file"]).read_bytes()
    root = backend.firmware_high_root
    runs = []
    current = []
    for mapping in mappings:
        address = int(mapping["va"])
        if current and address != int(current[-1]["va"]) + PAGE:
            runs.append(current)
            current = []
        current.append(mapping)
    if current:
        runs.append(current)

    # Establish all leaves first. Reusing present backing matters because the
    # cold-boot arena still owns and addresses those objects by physical PA.
    for run in runs:
        map_firmware(
            backend, int(run[0]["va"]),
            int(run[-1]["va"]) - int(run[0]["va"]) + PAGE)

    for mapping in mappings:
        address = int(mapping["va"])
        translated = backend.space.uat.iotranslate_root(root, address, PAGE)
        if not translated or translated[0][0] is None:
            raise RuntimeError(
                "captured firmware page %#x remained unmapped" % address)
        pa = translated[0][0]
        pte = int(mapping["pte"])
        backend.space.uat.iomap_at_root(
            root, address, pa, PAGE, ctx=backend.space.context,
            AttrIndex=(pte >> 2) & 7,
            AP=(pte >> 6) & 3,
            SH=(pte >> 8) & 3,
            AF=(pte >> 10) & 1,
            nG=(pte >> 11) & 1,
            PXN=(pte >> 53) & 1,
            UXN=(pte >> 54) & 1,
            OS=(pte >> 55) & 1,
        )
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi vmalle1os")
    backend.u.inst("dsb sy")

    copied = 0
    for run in runs:
        body = b"".join(
            ram[int(mapping["blob_index"]) * PAGE:
                (int(mapping["blob_index"]) + 1) * PAGE]
            for mapping in run
        )
        if len(body) != len(run) * PAGE:
            raise RuntimeError("native firmware-high payload is truncated")
        address = int(run[0]["va"])
        backend._write_dva(address, body)
        backend._clean_dva_range(address, len(body))
        copied += len(run)
    backend.u.inst("dsb sy")
    print(
        "COMPUTE restored complete captured firmware-high image: "
        "%d pages (%#x bytes) in %d runs under root %#x" %
        (copied, copied * PAGE, len(runs), root),
        flush=True,
    )
    return {
        "pages": copied,
        "runs": len(runs),
        "root_index": int(groups[0]["root_index"]),
    }


def install_native_context2(backend):
    """Install the complete captured context-2 low tree in native slot 12."""
    manifest = json.loads((NATIVE_CLIENT_SNAPSHOT / "manifest.json").read_text())
    groups = [
        group for group in manifest["root_mappings"]
        if int(group.get("root_ctx_id", -1)) == 2
        and int(group.get("selector", -1)) == 0
    ]
    if len(groups) != 1:
        raise RuntimeError(
            "native snapshot has %d context-2 low roots, expected one" %
            len(groups))
    hardware_slot = int(groups[0]["root_index"])
    mappings = sorted(
        (mapping for mapping in groups[0]["mappings"]
         if mapping.get("blob_index") is not None),
        key=lambda mapping: int(mapping["va"]),
    )
    if not mappings:
        raise RuntimeError("native context-2 root contains no captured pages")

    ram = (NATIVE_CLIENT_SNAPSHOT / manifest["ram_file"]).read_bytes()
    payload = b"".join(
        ram[int(mapping["blob_index"]) * PAGE:
            (int(mapping["blob_index"]) + 1) * PAGE]
        for mapping in mappings
    )
    if len(payload) != len(mappings) * PAGE:
        raise RuntimeError("native context-2 payload is truncated")

    uat = backend.space.uat
    logical_slot_base = uat.gpu_region + 2 * 16
    displaced_roots = (
        TTBR(backend.u.proxy.read64(logical_slot_base)),
        TTBR(backend.u.proxy.read64(logical_slot_base + 8)),
    )
    state = backend.create_execution_context(2)
    space = state["space"]
    base_pa = backend.u.memalign(PAGE, len(payload))
    backend.u.iface.writemem(base_pa, payload)
    backend.u.proxy.dc_civac(base_pa, len(payload))
    for index, mapping in enumerate(mappings):
        address = int(mapping["va"])
        pte = int(mapping["pte"])
        space.uat.iomap_at(
            space.context, address, base_pa + index * PAGE, PAGE,
            AttrIndex=(pte >> 2) & 7,
            AP=(pte >> 6) & 3,
            SH=(pte >> 8) & 3,
            AF=(pte >> 10) & 1,
            nG=(pte >> 11) & 1,
            PXN=(pte >> 53) & 1,
            UXN=(pte >> 54) & 1,
            OS=(pte >> 55) & 1,
        )

    native_high_root = backend.u.memalign(PAGE, PAGE)
    backend.u.proxy.memset32(native_high_root, 0, PAGE)
    backend.u.proxy.dc_civac(native_high_root, PAGE)
    space.uat.set_l0(hardware_slot, 0, space.uat.ttbr0_base, 2)
    space.uat.set_l0(hardware_slot, 1, native_high_root, 2)
    for selector, root in enumerate(displaced_roots):
        base = (root.BADDR << 1) if root.VALID else 0
        space.uat.set_l0(2, selector, base, root.ASID)
    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi vmalle1os")
    backend.u.inst("dsb sy")
    print(
        "COMPUTE installed complete captured context-2 image: %d pages "
        "(%#x bytes) in native hardware slot %d; restored displaced slot 2" %
        (len(mappings), len(payload), hardware_slot),
        flush=True,
    )
    return {
        "space": space,
        "pages": len(mappings),
        "hardware_slot": hardware_slot,
    }


def dump_hardware_uat_slots(backend):
    """Show exactly which accelerator-visible roots resolve the client graph."""
    probes = (
        ("shader", SHADER),
        ("resource", RESOURCE),
        ("cdm", CDM),
        ("output", BUFFER_OUT),
    )
    uat = backend.space.uat
    uat.invalidate_cache()
    table = backend.u.iface.readmem(
        uat.gpu_region, uat.NUM_CONTEXTS * 16)
    for slot in range(uat.NUM_CONTEXTS):
        low = TTBR(struct.unpack_from("<Q", table, slot * 16)[0])
        high = TTBR(struct.unpack_from("<Q", table, slot * 16 + 8)[0])
        if not low.VALID or low.ASID != backend.primary_execution_context:
            continue
        translations = []
        for name, address in probes:
            ranges = uat.iotranslate(slot, address, 1)
            translations.append(
                "%s=%s" % (
                    name,
                    "unmapped" if not ranges or ranges[0][0] is None
                    else "%#x" % ranges[0][0],
                )
            )
        print(
            "COMPUTE UAT slot=%d low_valid=%d low_asid=%d low_root=%#x "
            "high_valid=%d high_asid=%d high_root=%#x %s" % (
                slot, low.VALID, low.ASID, low.BADDR << 1,
                high.VALID, high.ASID, high.BADDR << 1,
                " ".join(translations),
            ),
            flush=True,
        )


def coherent_dva_read(backend, address, size):
    if backend.firmware_root == "high" and address >= 0xFFFF000000000000:
        ranges = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, address, size)
    else:
        ranges = backend.space.uat.iotranslate(
            backend.space.context, address, size)
    remaining = size
    for pa, span in ranges:
        if pa is None:
            raise RuntimeError("cannot sample unmapped DVA %#x" % address)
        length = min(span, remaining)
        backend.u.proxy.dc_ivac(pa, length)
        remaining -= length
        if not remaining:
            break
    if remaining:
        raise RuntimeError("short translation while sampling DVA %#x" % address)
    return backend._read_dva(address, size)


def audit_exact_cl2_pointer_closure(backend, entry, queue):
    """Require every pointer in the generated CL2 graph to name real state.

    The fixed DVAs mirror one native publication, but address equality is not
    useful unless each address translates through the consumer's UAT view to
    the object we constructed.  Keep this audit read-only and immediately
    before the doorbell so its output describes the graph firmware receives.
    """
    uat = backend.space.uat
    uat.invalidate_cache()

    def direct_pte(address):
        page = address & ~(PAGE - 1)
        table = backend.firmware_high_root
        pte = None
        for offset, size, ptecls in uat.LEVELS[1:]:
            index = (page >> offset) & (size - 1)
            pte = uat.fetch_pte(table, index, size, ptecls)
            if not pte.valid():
                break
            table = pte.offset()
        return pte

    def resolve(label, view, address, size=1, expected=None):
        address = int(address)
        size = int(size)
        if not address:
            raise RuntimeError("CL2 pointer %s is null" % label)
        if view == "fw":
            ranges = uat.iotranslate_root(
                backend.firmware_high_root, address, size)
            pte = direct_pte(address)
            read = lambda: uat.ioread_root(
                backend.firmware_high_root, address, size)
        else:
            context = int(view)
            ranges = uat.iotranslate(context, address, size)
            pte = uat.ioperm(context, address)
            read = lambda: uat.ioread(context, address, size)
        if not ranges or any(pa is None for pa, _span in ranges):
            raise RuntimeError(
                "CL2 pointer %s (%s:%#x+%#x) is unmapped" %
                (label, view, address, size))
        remaining = size
        for pa, span in ranges:
            take = min(remaining, span)
            backend.u.proxy.dc_ivac(pa, take)
            remaining -= take
            if not remaining:
                break
        body = bytes(read())
        if len(body) != size:
            raise RuntimeError(
                "CL2 pointer %s read %#x bytes, expected %#x" %
                (label, len(body), size))
        if expected is not None and body != expected:
            raise RuntimeError(
                "CL2 pointer %s target bytes do not match their constructor" %
                label)
        print(
            "COMPUTE CL2 pointer %-30s %s:%#x -> pa=%#x "
            "pte=%#x nonzero=%d head=%s" % (
                label, view, address, ranges[0][0], int(pte),
                sum(byte != 0 for byte in body), body[:16].hex()),
            flush=True,
        )
        return body, ranges[0][0]

    def qword(body, offset):
        return struct.unpack_from("<Q", body, offset)[0]

    def require_context3_range(label, address, size):
        ranges = uat.iotranslate(3, address, size)
        covered = sum(span for pa, span in ranges if pa is not None)
        if (not ranges or any(pa is None for pa, _span in ranges)
                or covered != size):
            raise RuntimeError(
                "%s is not fully mapped in context 3: %r" %
                (label, ranges))
        for probe in (address, address + size - PAGE):
            pte = uat.ioperm(3, probe)
            if int(pte) & 0xFFF != 0xC8B:
                raise RuntimeError(
                    "%s has non-native PTE %#x at %#x" %
                    (label, int(pte), probe))
        context1 = uat.iotranslate(1, address, 1)
        if (context1 and context1[0][0] is not None
                and context1[0][0] == ranges[0][0]):
            raise RuntimeError(
                "%s aliases context 1 at PA %#x" %
                (label, ranges[0][0]))
        print(
            "COMPUTE CL2 context3 %-25s %#x+%#x mapped, pte=0xc8b, "
            "context1_pa=%s" % (
                label, address, size,
                "%#x" % context1[0][0]
                if context1 and context1[0][0] is not None else "unmapped"),
            flush=True,
        )

    require_context3_range(
        "operand page-list region",
        OPERAND_PAGE_LIST_BASE, OPERAND_PAGE_LIST_REGION_SIZE)
    resolve(
        "operand page-list records", 3, OPERAND_PAGE_LIST_BASE, 3 * PAGE,
        compute.build_compute_operand_page_lists(OPERAND_BUFFER_BASE))
    resolve(
        "operand page-list zero tail head", 3,
        OPERAND_PAGE_LIST_BASE + 3 * PAGE, 0x40, bytes(0x40))
    resolve(
        "operand page-list zero tail end", 3,
        OPERAND_PAGE_LIST_BASE + OPERAND_PAGE_LIST_REGION_SIZE - 0x40,
        0x40, bytes(0x40))
    require_context3_range(
        "operand table region", CLIENT_STATE, OPERAND_TABLE_REGION_SIZE)
    resolve(
        "operand table region zero tail", 3, CLIENT_STATE + PAGE,
        OPERAND_TABLE_REGION_SIZE - PAGE,
        bytes(OPERAND_TABLE_REGION_SIZE - PAGE))
    require_context3_range(
        "client state region", CLIENT_STATE_ZERO, CLIENT_STATE_REGION_SIZE)
    resolve(
        "client state region bytes", 3, CLIENT_STATE_ZERO,
        CLIENT_STATE_REGION_SIZE, bytes(CLIENT_STATE_REGION_SIZE))

    queue_body, _queue_pa = resolve(
        "channel slot -> queue", "fw", QUEUE,
        g17p.QUEUE_RECORD_STRIDE)
    queue_fields = (
        ("queue -> pointer block", g17p.QUEUE_POINTERS_ADDR,
         QUEUE_POINTERS, 0x80),
        ("queue -> item ring", g17p.QUEUE_RING_ADDR, ITEM_RING, PAGE),
        ("queue -> job list", g17p.QUEUE_JOB_LIST_ADDR, JOB_LIST, 0x60),
        ("queue -> channel record", g17p.QUEUE_CONTEXT_ADDR,
         CHANNEL_CONTROL, backend.CHANNEL_CONTROL_STRIDE),
    )
    for label, offset, expected_address, size in queue_fields:
        address = qword(queue_body, offset)
        if address != expected_address:
            raise RuntimeError(
                "%s is %#x, expected %#x" %
                (label, address, expected_address))
        resolve(label, "fw", address, size)

    ring_slot = coherent_dva_read(
        backend, entry["ring_addr"], g17p.RING_SLOT_SIZE)
    if qword(ring_slot, g17p.RING_SLOT_QUEUE_PTR) != QUEUE:
        raise RuntimeError("CL2 outer ring does not point at generated queue")
    print(
        "COMPUTE CL2 pointer %-30s fw:%#x -> fw:%#x" %
        ("outer ring -> queue", entry["ring_addr"], QUEUE),
        flush=True,
    )

    item_ring, _ = resolve("queue -> populated items", "fw", ITEM_RING, 0x18)
    item_addresses = struct.unpack_from("<3Q", item_ring)
    expected_items = (DESCRIPTOR, OPTIONAL, EVENT)
    if item_addresses != expected_items:
        raise RuntimeError(
            "CL2 item ring is %r, expected %r" %
            (item_addresses, expected_items))
    descriptor, descriptor_pa = resolve(
        "item[0] -> compute descriptor", "fw", DESCRIPTOR,
        compute.COMPUTE_DESCRIPTOR_SIZE)
    native_client = descriptor == native_compute_descriptor()
    full_native_context = (
        native_client
        and os.getenv("G17P_COMPUTE_NATIVE_FULL_CONTEXT") == "1")
    print(
        "COMPUTE CL2 descriptor profile=%s" %
        ("native-t256" if native_client else "generated-add3"),
        flush=True,
    )
    optional, _ = resolve(
        "item[1] -> optional", "fw", OPTIONAL,
        compute.COMPUTE_OPTIONAL_SIZE)
    resolve("item[2] -> event", "fw", EVENT, EVENT_RECORD_SIZE)

    descriptor_low, descriptor_low_pa = resolve(
        "descriptor low alias", 0, DESCRIPTOR_LOW,
        compute.COMPUTE_DESCRIPTOR_SIZE)
    if descriptor_low_pa != descriptor_pa or descriptor_low != descriptor:
        raise RuntimeError("compute descriptor high/low aliases differ")
    for label, offset, expected_address in (
            ("primary register locator", 0x740,
             DESCRIPTOR_LOW + compute.COMPUTE_REGISTER_START),
            ("secondary register locator", 0xE60,
             DESCRIPTOR_LOW + compute.COMPUTE_SECONDARY_REGISTER_START)):
        address = qword(descriptor, offset)
        if address != expected_address:
            raise RuntimeError(
                "%s is %#x, expected %#x" %
                (label, address, expected_address))
        resolve(label, 0, address, 0x30)

    if native_client:
        descriptor_targets = (
            ("descriptor -> scheduler", 0x10, "fw",
             0xFFFFFC20C0998100, 0x100),
            ("descriptor -> resource", 0xED8, 3,
             NATIVE_RESOURCE, RESOURCE_SIZE),
            ("descriptor -> dispatch A", 0xF40, "fw",
             0xFFFFFC20001C8028, 8),
            ("descriptor -> dispatch B", 0xF48, "fw",
             0xFFFFFC20C07C0028, 8),
            ("descriptor -> status A", 0xF7C, "fw",
             0xFFFFFC2000024C78, 8),
            ("descriptor -> status B", 0xF84, "fw",
             0xFFFFFC2000024C80, 8),
            ("descriptor -> shared support", 0xFB2, "fw",
             0xFFFFFC20C09A0000, PAGE),
            ("descriptor -> zero page", 0xFCB, "fw",
             0xFFFFFC2001718000, PAGE),
        )
    else:
        descriptor_targets = (
            ("descriptor -> scheduler", 0x10, "fw", SCHEDULER, 0x100),
            ("descriptor -> resource", 0xED8, 3, RESOURCE, RESOURCE_SIZE),
            ("descriptor -> dispatch A", 0xF40, "fw", DISPATCH_A, 8),
            ("descriptor -> dispatch B", 0xF48, "fw", DISPATCH_B, 8),
            ("descriptor -> status A", 0xF7C, "fw", STATUS_A, 8),
            ("descriptor -> status B", 0xF84, "fw", STATUS_B, 8),
            ("descriptor -> shared support", 0xFB2, "fw",
             SHARED_SUPPORT, PAGE),
            ("descriptor -> zero page", 0xFCB, "fw", ZERO_PAGE, PAGE),
        )
    for label, offset, view, expected_address, size in descriptor_targets:
        address = qword(descriptor, offset)
        if address != expected_address:
            raise RuntimeError(
                "%s is %#x, expected %#x" %
                (label, address, expected_address))
        resolve(label, view, address, size)

    resource_base = NATIVE_RESOURCE if native_client else RESOURCE
    cdm_base = NATIVE_CDM if native_client else CDM
    output_base = NATIVE_OUTPUT if native_client else ROBUSTNESS
    register_targets = {
        0x1A510: ("register resource base", resource_base),
        0x1A420: ("register CDM base", cdm_base),
        0x1A4D0: ("register resource +0x1480", resource_base + 0x1480),
        0x1A4D8: ("register resource +0x1488", resource_base + 0x1488),
        0x1A4E0: ("register resource +0x1490", resource_base + 0x1490),
        0x1A4E8: ("register resource +0x1498", resource_base + 0x1498),
        0x14070: ("register robustness", output_base | 1),
        0x10229: ("register scratch +0xa800", SCRATCH + 0xA800),
        0x140A8: ("register scratch +0xb000", SCRATCH + 0xB000),
        0x10099: ("register scratch +0x1405", SCRATCH + 0x1405),
        0x10091: ("register scratch +0xa400", SCRATCH + 0xA400),
        0x0A5C1: ("register client state +0x18005", CLIENT_STATE_ZERO + 5),
        0x0A5C9: ("register scratch +0x1000", SCRATCH + 0x1000),
    }
    seen_register_targets = set()
    primary_register_values = {}
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        number, value = struct.unpack_from(
            "<IQ", descriptor,
            compute.COMPUTE_REGISTER_START
            + index * compute.COMPUTE_REGISTER_SIZE)
        if number == 0 and value == 0:
            break
        primary_register_values.setdefault(number, value)
        target = register_targets.get(number)
        if target is None or number in seen_register_targets:
            continue
        label, expected_address = target
        if value != expected_address:
            raise RuntimeError(
                "%s is %#x, expected %#x" %
                (label, value, expected_address))
        resolve(label, 3, value & ~1, 8)
        seen_register_targets.add(number)
    missing_registers = set(register_targets) - seen_register_targets
    if missing_registers:
        raise RuntimeError(
            "compute descriptor omits pointer registers %s" %
            ", ".join("%#x" % number for number in sorted(missing_registers)))
    for index, (destination, source) in enumerate(
            compute.COMPUTE_SECONDARY_REGISTERS):
        number, value = struct.unpack_from(
            "<IQ", descriptor,
            compute.COMPUTE_SECONDARY_REGISTER_START
            + index * compute.COMPUTE_REGISTER_SIZE)
        expected_value = primary_register_values[source]
        if number != destination or value != expected_value:
            raise RuntimeError(
                "secondary register %d is (%#x, %#x), expected (%#x, %#x)" %
                (index, number, value, destination, expected_value))
        resolve(
            "secondary register[%d] %#x<-0x%x" %
            (index, destination, source),
            3, value & ~1, 8)
    resolve(
        "0x0a5c1 blank state object", 3, CLIENT_STATE_ZERO, PAGE,
        bytes(PAGE))

    cdm, _ = resolve(
        "CDM stream", 3, cdm_base, compute.CDM_RECORD_SIZE + 4)
    terminator = qword(descriptor, 0xEE0)
    if terminator != cdm_base + compute.CDM_RECORD_SIZE:
        raise RuntimeError(
            "CDM terminator is %#x, expected %#x" %
            (terminator, cdm_base + compute.CDM_RECORD_SIZE))
    resolve(
        "descriptor -> CDM terminator", 3, terminator, 4,
        struct.pack("<I", compute.CDM_TERMINATOR))
    encoded_shader = qword(cdm, 8)
    shader_control = encoded_shader >> 32
    shader = ((encoded_shader & 0xFFFFFFFF) << 6
              | ((shader_control & 0x3FFFFFFF) << 40))
    expected_shader = NATIVE_SHADER if native_client else SHADER
    if shader != expected_shader:
        raise RuntimeError(
            "CDM shader encoding resolves %#x, expected %#x" %
            (shader, expected_shader))
    resolve(
        "CDM dispatch -> shader", 3, shader, len(ADD3_SHADER),
        None if native_client else ADD3_SHADER)

    resource, _ = resolve(
        "resource argument table", 3, resource_base, RESOURCE_SIZE)
    if native_client:
        for index in range(3):
            address = qword(resource, 0x14A0 + index * 8)
            if address:
                resolve("resource arg[%d]" % index, 3, address, 8)
    else:
        for index, expected_address in enumerate(
                (BUFFER_A, BUFFER_B, BUFFER_OUT)):
            address = qword(resource, 0x14A0 + index * 8)
            if address != expected_address:
                raise RuntimeError(
                    "resource argument %d is %#x, expected %#x" %
                    (index, address, expected_address))
            resolve("resource arg[%d]" % index, 3, address, PAGE)

    context_low = qword(optional, 0x08)
    context_high = qword(optional, 0x10)
    if context_low != QUEUE_CONTEXT_LOW or context_high != QUEUE_CONTEXT_HIGH:
        raise RuntimeError("compute optional carries the wrong context aliases")
    low_context, low_context_pa = resolve(
        "optional -> context low", 0, context_low, PAGE)
    high_context, high_context_pa = resolve(
        "optional -> context high", "fw", context_high, PAGE)
    if low_context_pa != high_context_pa or low_context != high_context:
        raise RuntimeError("compute queue-context aliases differ")
    if qword(high_context, 0x210) != DESCRIPTOR:
        raise RuntimeError("queue context does not point at descriptor")
    if qword(high_context, 0x218) != QUEUE:
        raise RuntimeError("queue context does not point at queue")
    resolve("context -> descriptor", "fw", DESCRIPTOR, PAGE)
    resolve("context -> queue", "fw", QUEUE, g17p.QUEUE_RECORD_STRIDE)
    for label, offset, expected_address, size in (
            ("optional -> shared support", 0x36, SHARED_SUPPORT, PAGE),
            ("optional -> channel record", 0x4A, CHANNEL_CONTROL,
             backend.CHANNEL_CONTROL_STRIDE)):
        address = qword(optional, offset)
        if address != expected_address:
            raise RuntimeError(
                "%s is %#x, expected %#x" %
                (label, address, expected_address))
        resolve(label, "fw", address, size)

    scheduler, _ = resolve("scheduler record", "fw", SCHEDULER, 0x100)
    if qword(scheduler, 0) != SCHEDULER_SLOT:
        raise RuntimeError("scheduler record carries the wrong slot pointer")
    resolve("scheduler -> slot", "fw", SCHEDULER_SLOT, 0x40)
    scheduler_page, _ = resolve(
        "scheduler page -> shared state", "fw", SCHEDULER_PAGE, 8)
    if qword(scheduler_page, 0) != SHARED_STATE:
        raise RuntimeError("scheduler page carries the wrong shared-state pointer")
    resolve("scheduler page -> shared state", "fw", SHARED_STATE, PAGE)

    shared, _ = resolve("shared support", "fw", SHARED_SUPPORT, PAGE)
    if qword(shared, 0x30) != CLIENT_STATE:
        raise RuntimeError("shared support carries the wrong operand table")
    operand_table, _ = resolve(
        "shared support -> operand table", 3, CLIENT_STATE, PAGE,
        compute.build_compute_operand_table(OPERAND_BUFFER_BASE))
    for index in range(compute.COMPUTE_OPERAND_TABLE_ENTRIES):
        address = (
            OPERAND_BUFFER_BASE
            + index * compute.COMPUTE_OPERAND_BUFFER_STRIDE)
        tagged = qword(
            operand_table,
            index * compute.COMPUTE_OPERAND_TABLE_STRIDE)
        expected_tagged = address | compute.COMPUTE_OPERAND_BUFFER_FLAG
        if tagged != expected_tagged:
            raise RuntimeError(
                "operand table entry %d is %#x, expected %#x" %
                (index, tagged, expected_tagged))
        ranges = uat.iotranslate(
            3, address, compute.COMPUTE_OPERAND_BUFFER_SIZE)
        covered = sum(length for pa, length in ranges if pa is not None)
        if (not ranges or any(pa is None for pa, _length in ranges)
                or covered != compute.COMPUTE_OPERAND_BUFFER_SIZE):
            raise RuntimeError(
                "operand tranche %d at %#x is not fully mapped: %r" %
                (index, address, ranges))
        if (not full_native_context
                and index + 1 < compute.COMPUTE_OPERAND_TABLE_ENTRIES):
            gap = uat.iotranslate(
                3, address + compute.COMPUTE_OPERAND_BUFFER_SIZE,
                compute.COMPUTE_OPERAND_BUFFER_STRIDE
                - compute.COMPUTE_OPERAND_BUFFER_SIZE)
            if any(pa is not None for pa, _length in gap):
                raise RuntimeError(
                    "operand tranche %d stride tail is mapped: %r" %
                    (index, gap))
        resolve(
            "operand tranche[%d] head" % index,
            3, address, 0x40, bytes(0x40))
        resolve(
            "operand tranche[%d] tail" % index,
            3,
            address + compute.COMPUTE_OPERAND_BUFFER_SIZE - 0x40,
            0x40, bytes(0x40))
        print(
            "COMPUTE CL2 operand tranche[%d] %#x -> pa=%#x length=%#x" %
            (index, address, ranges[0][0], covered),
            flush=True,
        )
    support_state = qword(shared, 0x4C)
    if support_state != SUPPORT_STATE:
        raise RuntimeError("shared support carries the wrong state pointer")
    resolve("shared support -> state", "fw", support_state, PAGE)

    job_list, _ = resolve("queue job-list head", "fw", JOB_LIST, 0x18)
    if qword(job_list, 0x08) != JOB_LIST:
        raise RuntimeError("fresh compute job-list head is not self-linked")

    predecessor, _ = resolve(
        "primary predecessor", "fw", PRIMARY_RECORD_PREDECESSOR, PAGE)
    native_predecessor_qwords = dict(NATIVE_COMPUTE_PREDECESSOR_U64)
    for index in range(5):
        offset = 0x800 + index * 8
        record = qword(predecessor, offset)
        expected_record = native_predecessor_qwords[offset]
        if record != expected_record:
            raise RuntimeError(
                "primary predecessor record %d is %#x, expected %#x" %
                (index, record, expected_record))
        resolve(
            "primary predecessor -> channel[%d]" % index,
            "fw", record, backend.CHANNEL_CONTROL_STRIDE)
    print("COMPUTE CL2 pointer closure: complete", flush=True)


def byte_delta(before, after):
    return ",".join(
        "%#x:%02x>%02x" % (offset, old, new)
        for offset, (old, new) in enumerate(zip(before, after))
        if old != new
    ) or "none"


def changed_offsets(before, after, limit=16):
    offsets = [offset for offset, values in enumerate(zip(before, after))
               if values[0] != values[1]]
    shown = ",".join("%#x" % offset for offset in offsets[:limit])
    if len(offsets) > limit:
        shown += ",..."
    return len(offsets), shown or "none"


def drain_boot_group(front, backend, *, require_output_witness=True):
    """Drain the unavoidable cold-boot render and optionally witness output.

    Caller-supplied payload manifests can intentionally replace the reference
    opening render's shader pages.  Such experiments still need to adopt the
    completed queue group, but the reference framebuffer is not a meaningful
    execution witness for them.
    """
    fences = {}
    for kind, (entry, queue) in backend.muxed_queue_pair(0).items():
        indices = queue.indices()
        counters = backend.channels.counters(entry)
        published = {
            "write_after": indices["write"],
            "producer": counters[2],
            "consumers_before": counters[:2],
        }
        fences[kind] = G17PQueueFence(
            backend.submitter,
            entry,
            queue,
            published,
            name="cold-boot render %s" % kind,
        )

    already_completed = [fence.signaled() for fence in fences.values()]
    if any(already_completed):
        if not all(already_completed):
            raise RuntimeError(
                "native-opening render completed on only one queue: %r" %
                {kind: fence.snapshot() for kind, fence in fences.items()})
        page = None
        if require_output_witness:
            runtime = front.g17p_runtime or {}
            pages = list(runtime.get("render_execution_pages") or ())
            pages.sort(key=lambda page: page["name"] != "load_store_pipelines")
            if not pages:
                raise RuntimeError(
                    "native-opening render fences signaled without captured output bytes")
            page = pages[0]
            if page["before"] == page["after"]:
                raise RuntimeError(
                    "native-opening render witness did not change physical bytes")
        backend.adopt_completed_staged_group()
        if page is not None:
            print(
                "COMPUTE adopted native-opening render witness %s at %#x: %d bytes changed" %
                (page["name"], page["dva"],
                 sum(old != new for old, new in zip(page["before"], page["after"]))),
                flush=True,
            )
        else:
            print(
                "COMPUTE adopted completed native-opening render without "
                "reference-output requirement",
                flush=True,
            )
        return {
            "target_dva": None if page is None else page["dva"],
            "target_pa": None if page is None else page["pa"],
            "before": None if page is None else page["before"],
            "after": None if page is None else page["after"],
            "fences": fences,
            "fence_snapshots": {
                kind: fence.snapshot() for kind, fence in fences.items()
            },
        }

    _dva, target_pa = map_client(
        backend, RENDER_WITNESS, PAGE, "compute_boot_witness")
    backend.bind_color_attachment(RENDER_WITNESS, PAGE, 64, 64)
    backend.space.flush()
    backend.u.inst("dsb sy")
    before = physical_read(backend, target_pa, PAGE)
    backend.submitter.notify(work_doorbell_channel(0))
    deadline = time.monotonic() + COMPLETION_TIMEOUT
    after_head = before[:32]
    while time.monotonic() < deadline:
        after_head = physical_read(backend, target_pa, 32)
        if after_head != before[:32]:
            break
        time.sleep(0.0001)
    if after_head == before[:32]:
        raise RuntimeError("cold-boot group did not change its physical target")
    for fence in fences.values():
        fence.wait(timeout=COMPLETION_TIMEOUT, event_pump=backend.event_pump)
    after = physical_read(backend, target_pa, PAGE)
    if after == before:
        raise RuntimeError("cold-boot group fence signaled without target output")
    if backend.control_done is not None:
        backend.control_done()
    if backend.event_pump is not None:
        backend.event_pump()
    backend.adopt_completed_staged_group()
    return {
        "target_dva": RENDER_WITNESS,
        "target_pa": target_pa,
        "before": before,
        "after": after,
        "fences": fences,
        "fence_snapshots": {
            kind: fence.snapshot() for kind, fence in fences.items()
        },
    }


def prepare_runtime_registration(front, backend):
    """Build the queue-pair furniture that precedes native registration."""
    state = getattr(front, "g17p_submission_state", None) or {}
    pointers = {
        kind: dict(state.get("%s_optional" % kind) or {})
        for kind in ("tiling", "fragment")
    }
    if any("shared_control" not in value for value in pointers.values()):
        raise RuntimeError(
            "cold boot did not export complete runtime optional pointers")
    backend.create_muxed_queue_pair(1, pointers)
    builder = backend.paired_builder_for(1)
    if builder.leaf_pages is None:
        builder.build_submission_graph()
    for _name, address, size in backend.MUX_PAIR1_GRAPH:
        backend._clean_dva_range(address, size)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "COMPUTE built the complete pair-1 resource graph before control",
        flush=True,
    )


def create_render_cadence_workload(front):
    """Allocate independent physical witnesses for the final-26.6 prefix."""
    target_count = FINAL_26_6_RENDER_PREFIX_COUNT - 1
    target_stride = 0x100000000
    os.ftruncate(front.memfd, target_count * PAGE)
    targets = []
    first_address = None
    for index in range(target_count):
        offset = index * PAGE
        if index:
            front.ctx.gobj.next_va = first_address + index * target_stride
        address = front.create_bo_from_memfd(
            front.memfd, offset, PAGE, 0)
        if first_address is None:
            first_address = address
        target = front.bos[offset]
        target._no_push = True
        targets.append({"address": address, "target": target})
    print(
        "COMPUTE allocated %d independent render-cadence witnesses" %
        target_count,
        flush=True,
    )
    return {"targets": targets, "next_target": 0}


def run_render_cadence_submission(front, backend, workload, label):
    """Execute one render and require its independent physical output."""
    index = workload["next_target"]
    if index >= len(workload["targets"]):
        raise RuntimeError("render-cadence witness pool exhausted")
    workload["next_target"] = index + 1
    witness = workload["targets"][index]
    address = witness["address"]
    target = witness["target"]
    backend.u.proxy.memset32(target._pa, 0, PAGE)
    backend.u.proxy.dc_civac(target._pa, PAGE)
    before = physical_read(backend, target._pa, 32)
    if any(before):
        raise RuntimeError("%s target is not fresh" % label)

    body = packed_cmdbuf(
        64, 64,
        color_attachment={"type": 0, "size": PAGE, "pointer": address},
    )
    storage = ctypes.create_string_buffer(body)
    args = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))
    result = front.submit(front.memfd, args)
    after = physical_read(backend, target._pa, 32)
    submission = backend.last_submission
    if submission is None:
        raise RuntimeError("%s produced no submission record" % label)
    if after == before:
        raise RuntimeError(
            "%s retired without changing its physical target" % label)
    submission["semantic_witness_pa"] = target._pa
    submission["semantic_witness_dva"] = address
    submission["semantic_witness_before"] = before
    submission["output_changed"] = True
    print(
        "COMPUTE %s result=%r ordinal=%d pair=%d target=%#x changed" % (
            label, result, submission["submission_ordinal"],
            submission["queue_pair"], address,
        ),
        flush=True,
    )
    return submission


def prepare_native_primary_pair2_graph(backend):
    """Build the context-2 graph used by native outer slots 4 and 5."""
    from m1n1.agx import g17p_submission as submission

    if 2 not in backend.muxed_queue_pairs:
        optional = backend.muxed_queue_pointer_sets.get(1)
        if optional is None:
            raise RuntimeError("primary pair-2 setup needs pair-1 pointers")
        # Native primary TA/3D outer slots 4 and 5 use the fixed grid-4/5
        # queue records, pointer blocks and item rings also used when the
        # context-2 channels become directly visible later in the lifecycle.
        backend.native_context2_primary_channel = True
        backend.create_muxed_queue_pair(2, optional, channel_pair=0)

    for address, size in (
            (PRIMARY_PAIR2_PRIMARY, PAGE),
            (PRIMARY_PAIR2_SECONDARY, PAGE),
            (PRIMARY_PAIR2_SHARED_SLOTS, PAGE),
            (PRIMARY_PAIR2_FLAG, PAGE),
            (PRIMARY_PAIR2_POOL_B, 0x2780),
            (PRIMARY_PAIR2_SHARED, 0x88),
            (PRIMARY_PAIR2_ZERO, 0x100)):
        backend._ensure_firmware_range(address, size)

    leaves = submission.build_submission_leaf_pages(
        pair_index=2,
        index_group_ranges=((0x11, 6), (0x3c, 2)),
        shared_count=8,
    )
    leaf_addresses = {
        "primary_index": PRIMARY_PAIR2_PRIMARY,
        "secondary_index": PRIMARY_PAIR2_SECONDARY,
        "pool_a_slots": PRIMARY_PAIR2_POOL_A_SLOTS,
        "pool_b_slots": PRIMARY_PAIR2_POOL_B_SLOTS,
        "shared_slots": PRIMARY_PAIR2_SHARED_SLOTS,
        "flag": PRIMARY_PAIR2_FLAG,
    }
    for name in ("primary_index", "secondary_index", "shared_slots", "flag"):
        backend._write_dva(leaf_addresses[name], leaves[name])
    backend._write_dva(
        PRIMARY_PAIR2_POOL_B,
        submission.build_record_array_b(
            PRIMARY_PAIR2_POOL_B_SLOTS + submission.POOL_B_SLOT_OFFSET,
            PRIMARY_PAIR2_SHARED_SLOTS + submission.SHARED_SLOT_OFFSET,
            pair_index=0,
        ),
    )
    packed = bytearray(submission.build_shared_object((
        PRIMARY_PAIR2_PRIMARY,
        PRIMARY_PAIR2_SECONDARY,
        PRIMARY_PAIR2_SHARED_SLOTS,
        PRIMARY_PAIR2_FLAG,
    ), pair_index=2))
    struct.pack_into("<I", packed,
                     submission.SHARED_OBJECT_PAIR_INDEX_OFFSET, 2)
    for offset, value in ((0x34, 0x20), (0x3c, 8), (0x54, 0x1f)):
        struct.pack_into("<I", packed, offset, value)
    backend._write_dva(PRIMARY_PAIR2_SHARED, packed)
    backend._write_dva(
        PRIMARY_PAIR2_ZERO, submission.build_zero_shared_object())

    builder = backend.paired_builder_for(2, 2)
    builder.leaf_pages = leaf_addresses
    builder.tiling.use_pools(PRIMARY_PAIR2_POOL_A, PRIMARY_PAIR2_POOL_B)
    builder.fragment.use_pools(PRIMARY_PAIR2_POOL_A, PRIMARY_PAIR2_POOL_B)
    builder.shared = (PRIMARY_PAIR2_SHARED, PRIMARY_PAIR2_ZERO)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "COMPUTE built native primary pair-2 graph at %#x/%#x" %
        (PRIMARY_PAIR2_POOL_A, PRIMARY_PAIR2_POOL_B),
        flush=True,
    )


def snapshot_generated_render_slot(backend, slot, pair):
    """Save host-built pair state at the last point before its work doorbell."""
    from m1n1.agx import g17p_submission as submission

    stamp = time.strftime("%Y%m%d_%H%M%S")
    outdir = pathlib.Path(
        "/Users/user/asahi_re/artifacts/agx_g17p/generated_render_slot%d_pre_notify_%s" %
        (slot, stamp))
    outdir.mkdir(parents=True, exist_ok=False)

    ordinal = backend.group_number
    published = backend.last_published_pair or {}

    def published_item(kind, position, array_name):
        items = published.get(kind)
        if items and len(items) > position:
            return int(items[position])
        # Retain the old fallback for callers that intentionally snapshot a
        # builder before it has staged anything.  A pre-notify hook always has
        # last_published_pair and therefore takes the exact queue item instead
        # of an unrelated global-ordinal array slot.
        return (
            backend.ITEM_ARRAYS[array_name][0]
            + ordinal * backend.ITEM_ARRAYS[array_name][1]
        )

    ranges = {
        "tiling_descriptor": (
            published_item("tiling", 0, "tiling_descriptor"),
            backend.ITEM_ARRAYS["tiling_descriptor"][2]),
        "fragment_descriptor": (
            published_item("fragment", 0, "fragment_descriptor"),
            backend.ITEM_ARRAYS["fragment_descriptor"][2]),
        "tiling_optional": (
            published_item("tiling", 1, "tiling_optional_item"),
            backend.ITEM_ARRAYS["tiling_optional_item"][2]),
        "fragment_optional": (
            published_item("fragment", 1, "fragment_optional_item"),
            backend.ITEM_ARRAYS["fragment_optional_item"][2]),
        "tiling_event": (
            published_item("tiling", 2, "tiling_event_item"),
            backend.ITEM_ARRAYS["tiling_event_item"][2]),
        "fragment_event": (
            published_item("fragment", 2, "fragment_event_item"),
            backend.ITEM_ARRAYS["fragment_event_item"][2]),
        "channel_control": (backend.CHANNEL_CONTROL_BASE, PAGE),
        "current_jobs": (0xFFFFFC20C07D0000, 0x80),
    }

    # Preserve the complete optional-item control closure.  The final-26.6
    # opening and the beta-derived generated path can use different compact
    # support objects while every queue-local object still looks valid; omitting
    # these pages made that registration mismatch invisible in earlier dumps.
    pointer_sets = backend.muxed_queue_pointer_sets.get(pair, {})
    shared_controls = set()
    for kind, values in pointer_sets.items():
        for role in (
                "context_scratch", "firmware_scratch",
                "shared_control", "channel_control"):
            address = int(values.get(role, 0) or 0)
            if not address:
                continue
            ranges["%s_%s" % (kind, role)] = (address, PAGE)
            if role == "shared_control":
                shared_controls.add(address)
    for index, address in enumerate(sorted(shared_controls)):
        support = backend._read_dva(address, 0x80)
        inner = struct.unpack_from("<Q", support, 0x4c)[0]
        if inner:
            ranges["shared_control_%d_inner" % index] = (inner, PAGE)

    queues = backend.muxed_queue_pairs[pair]
    for kind, (_entry, queue) in queues.items():
        ranges["%s_queue" % kind] = (queue.address, g17p.QUEUE_RECORD_STRIDE)
        ranges["%s_queue_pointers" % kind] = (
            queue.pointers_addr, g17p.QUEUE_PTR_BLOCK_SIZE)
        ranges["%s_item_ring" % kind] = (queue.item_ring, 0x100)
        ranges["%s_job_list" % kind] = (
            queue.job_list_addr, g17p.JOB_LIST_SIZE)

    for kind, values in backend.muxed_queue_context_pages.get(pair, {}).items():
        ranges["%s_queue_context" % kind] = (
            values["high"],
            len(values["pas"]) * submission.FIRMWARE_PAGE_SIZE)

    # Fixed pair zero's context pages predate muxed_queue_context_pages. Read
    # their high and low aliases directly from the just-built optional items so
    # a mixed descriptor/transport experiment captures the exact queue-context
    # item it will publish, rather than only its descriptor and queue record.
    for kind in ("tiling", "fragment"):
        items = published.get(kind)
        if not items or len(items) < 2:
            continue
        optional = backend._read_dva(items[1], submission.OPTIONAL_ITEM_SIZE)
        low = struct.unpack_from("<Q", optional, 0x08)[0]
        high = struct.unpack_from("<Q", optional, 0x10)[0]
        if low:
            ranges.setdefault("%s_context_scratch" % kind, (low, PAGE))
        if high:
            ranges.setdefault(
                "%s_queue_context" % kind,
                (high, backend.MUX_PAIR1_CONTEXT_PAGES
                 * submission.FIRMWARE_PAGE_SIZE))

    # `paired_builders[pair]` describes the graph the current host builder owns,
    # but firmware can keep an earlier parameter-buffer graph bound while a
    # later descriptor reuses its four top-level objects.  Follow the actual
    # descriptor pointer block so a pre-notify dump contains that bound graph's
    # leaf closure, not merely the latest builder's parallel leaf pages.
    tiling_items = published.get("tiling")
    if tiling_items:
        descriptor = tiling_items[0]
        layout = submission.DESCRIPTOR_LAYOUT["tiling"]
        cursor = layout["pointers"]
        bound_objects = [
            struct.unpack(
                "<Q", backend._read_dva(descriptor + cursor, 8)
            )[0]
        ]
        cursor += 8 + layout["pointer_gap"]
        for _index in range(3):
            bound_objects.append(struct.unpack(
                "<Q", backend._read_dva(descriptor + cursor, 8)
            )[0])
            cursor += 8
        record_a, packed, record_b, zero_shared = bound_objects
        ranges.update({
            "bound_record_a": (record_a, submission.ARRAY_A_STRIDE),
            "bound_packed_shared": (packed, submission.SHARED_OBJECT_SIZE),
            "bound_record_b": (record_b, submission.ARRAY_B_STRIDE),
            "bound_zero_shared": (
                zero_shared, submission.ZERO_SHARED_OBJECT_SIZE),
        })

        record_a_slot = struct.unpack(
            "<Q", backend._read_dva(record_a, 8)
        )[0]
        record_b_slot = struct.unpack(
            "<Q", backend._read_dva(
                record_b + submission.ARRAY_B_SLOT_OFFSET, 8)
        )[0]
        record_b_shared = struct.unpack(
            "<Q", backend._read_dva(
                record_b + submission.ARRAY_B_SHARED_OFFSET, 8)
        )[0]
        nested = [
            struct.unpack(
                "<Q", backend._read_dva(packed + offset, 8)
            )[0]
            for offset in submission.SHARED_OBJECT_POINTER_OFFSETS
        ]
        bound_leaves = {
            "primary_index": nested[0],
            "secondary_index": nested[1],
            "pool_a_slots": record_a_slot,
            "pool_b_slots": record_b_slot,
            "shared_slots": nested[2],
            "flag": nested[3],
        }
        if ((record_b_shared & ~(PAGE - 1))
                != (bound_leaves["shared_slots"] & ~(PAGE - 1))):
            raise RuntimeError(
                "bound Pool-B shared pointer and packed object disagree: "
                "%#x != %#x" %
                (record_b_shared, bound_leaves["shared_slots"])
            )
        for name, address in bound_leaves.items():
            ranges["bound_leaf_%s" % name] = (
                address & ~(PAGE - 1), PAGE
            )

    builder = backend.paired_builders[pair]
    for name, address in (builder.leaf_pages or {}).items():
        ranges["leaf_%s" % name] = (address, PAGE)
    ranges.update({
        "pool_a": (builder.tiling.array_a, 0x2300),
        "pool_b": (builder.tiling.array_b, 0x2780),
        "shared": (builder.shared[0], 0x88),
        "shared_zero": (builder.shared[1], 0x100),
    })
    for name, obj in backend.render_objects.items():
        ranges["render_%s" % name] = (obj._addr, obj._size)

    manifest = {
        "format": "g17p-generated-render-pre-notify-v1",
        "slot": slot,
        "pair": pair,
        "submission_ordinal": ordinal,
        "ranges": [],
    }
    for name, (address, size) in sorted(ranges.items()):
        record = {"name": name, "dva": address, "size": size}
        try:
            body = backend._read_dva(address, size)
            filename = "%s_%016x.bin" % (name, address)
            (outdir / filename).write_bytes(body)
            record["file"] = filename
        except Exception as exc:  # noqa: BLE001
            record["error"] = str(exc)
        manifest["ranges"].append(record)
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("COMPUTE saved generated pre-notify slot %d state to %s" %
          (slot, outdir), flush=True)


def run_exact_render_cadence_submission(
        front, backend, workload, schedule):
    """Publish one render using a measured native outer-ring placement."""
    slot, pair, node, record_a, record_b, inner_count = schedule
    saved = (
        backend.forced_queue_pair,
        backend.forced_channel_pair,
        backend.forced_descriptor_pair,
        backend.forced_descriptor_context,
        backend.forced_scheduler_node,
        backend.forced_pool_record_indices,
        backend.omit_optional_item,
        backend.reuse_queue_items,
        backend.pre_notify_hook,
    )
    backend.forced_queue_pair = pair
    backend.forced_channel_pair = 0
    backend.forced_descriptor_pair = pair
    backend.forced_descriptor_context = 2 if pair == 2 else None
    backend.forced_scheduler_node = node
    backend.forced_pool_record_indices = (record_a, record_b)
    backend.omit_optional_item = inner_count == 2
    backend.reuse_queue_items = False
    if slot in (9, 10):
        previous_hook = backend.pre_notify_hook

        def snapshot_hook(active_backend, active_pair):
            if previous_hook is not None:
                previous_hook(active_backend, active_pair)
            snapshot_generated_render_slot(active_backend, slot, active_pair)

        backend.pre_notify_hook = snapshot_hook
    try:
        try:
            return run_render_cadence_submission(
                front, backend, workload,
                "native outer slot %d pair %d" % (slot, pair),
            )
        except RuntimeError as exc:
            if pair != 2 or "retired without changing" not in str(exc):
                raise
            submission = backend.last_submission
            if submission is None:
                raise RuntimeError(
                    "native pair-2 slot %d has no submission state" % slot)
            print(
                "COMPUTE native pair-2 slot %d retired without output; "
                "queues=%s scheduler_retired=%s" % (
                    slot,
                    {kind: submission[kind]["queue"].indices()
                     for kind in ("tiling", "fragment")},
                    backend.pair_retired(submission),
                ),
                flush=True,
            )
            witness = workload["targets"][workload["next_target"] - 1]["target"]
            submission["semantic_witness_pa"] = witness._pa
            submission["semantic_witness_before"] = bytes(32)
            submission["output_changed"] = False
            submission["awaiting_control_tick"] = True
            print(
                "COMPUTE native pair-2 slot %d awaiting the following "
                "measured control tick" % slot,
                flush=True,
            )
            return submission
    finally:
        (backend.forced_queue_pair,
         backend.forced_channel_pair,
         backend.forced_descriptor_pair,
         backend.forced_descriptor_context,
         backend.forced_scheduler_node,
         backend.forced_pool_record_indices,
         backend.omit_optional_item,
         backend.reuse_queue_items,
         backend.pre_notify_hook) = saved


def run_render_cadence(front, backend, runtime, expected_pair=None,
                       alternate_descriptor_pairs=False):
    """Generate 32 output-positive renders through control tick 30.

    Most source-transition experiments deliberately alternate the two logical
    queues.  A native forced-partial pass is different: its first 36 TA/3D
    publications all use the initial grid-0/1 queues, and it creates grid 2/3
    only after the first class-2 registration.  ``expected_pair`` lets that
    caller retain the shared physical-witness loop without inventing the
    pair-one lifetime too early.
    """
    workload = create_render_cadence_workload(front)
    work_count = 1
    output_positive_count = 1
    dependency_render = None
    for ordinal in range(2, FINAL_26_6_RENDER_PREFIX_COUNT + 1):
        saved_descriptor_pair = backend.forced_descriptor_pair
        if alternate_descriptor_pairs:
            backend.forced_descriptor_pair = (ordinal - 1) & 1
        try:
            result = run_render_cadence_submission(
                front, backend, workload, "final-26.6 render %d" % ordinal)
        finally:
            backend.forced_descriptor_pair = saved_descriptor_pair
        ordinal_pair = ((ordinal - 1) & 1
                        if expected_pair is None else int(expected_pair))
        if result["queue_pair"] != ordinal_pair:
            raise RuntimeError(
                "render %d selected pair %d, expected generated pair %d" %
                (ordinal, result["queue_pair"], ordinal_pair))
        if dependency_render is None:
            fences = {}
            fence_snapshots = {}
            for kind in ("tiling", "fragment"):
                state = result[kind]
                fence = G17PQueueFence(
                    backend.submitter,
                    state["entry"],
                    state["queue"],
                    state["published"],
                    name="render dependency %s" % kind,
                )
                snapshot = fence.snapshot()
                if not snapshot["signaled"]:
                    raise RuntimeError(
                        "output-positive render has an unsignaled %s fence: %r" %
                        (kind, snapshot))
                fences[kind] = fence
                fence_snapshots[kind] = snapshot
            target_pa = result["semantic_witness_pa"]
            after = physical_read(backend, target_pa, PAGE)
            if not any(after):
                raise RuntimeError(
                    "output-positive render has an all-zero full target page")
            dependency_render = {
                "target_dva": result["semantic_witness_dva"],
                "target_pa": target_pa,
                "before": bytes(PAGE),
                "after": after,
                "fences": fences,
                "fence_snapshots": fence_snapshots,
            }
        output_positive_count += 1
        work_count += 1

    print(
        "COMPUTE final-26.6 cadence reached %d publications, "
        "%d output-positive, at tick %#x" % (
            work_count, output_positive_count,
            FINAL_26_6_RENDER_PREFIX_COUNT - 2),
        flush=True,
    )
    if (work_count != FINAL_26_6_RENDER_PREFIX_COUNT or
            output_positive_count != work_count):
        raise RuntimeError(
            "final-26.6 render prefix was incomplete: %d/%d output-positive" %
            (output_positive_count, work_count))
    return {
        "workload": workload,
        "dependency_render": dependency_render,
    }


def prepare_context2_activation(backend):
    """Build the independent context-2 queue graph before class-2 publish."""
    optional_pointers = backend.muxed_queue_pointer_sets.get(1)
    if optional_pointers is None:
        raise RuntimeError("context-2 activation needs pair-one optionals")
    backend.create_muxed_queue_pair(3, optional_pointers, channel_pair=2)
    builder = backend.paired_builder_for(3, 1)
    if builder.leaf_pages is None:
        builder.build_submission_graph()
    backend._map_pair_status_aliases(1)

    for address, name in (
            (ACTIVATION_CONTROL_OPERAND, "activation_operand_table"),
            (ACTIVATION_LOW_BUFFER, "activation_low_buffer")):
        _dva, pa = map_client(
            backend, address, PAGE, name, reuse=True)
        backend.space.write(pa, bytes(PAGE))

    uat = backend.space.uat
    uat.set_l0(2, 0, uat.ttbr0_base, 2)
    uat.set_l0(2, 1, uat.ttbr1_base, 2)
    uat.flush_dirty()
    uat.invalidate_cache()
    backend.space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 2 << 48)
    backend.u.inst("dsb sy")
    print("COMPUTE installed generated context-2 roots and pair-3 graph", flush=True)


def execute_class2_activation_render(front, backend, optional_ordinal):
    """Run the physically witnessed work native places before the class-2 tick."""
    os.ftruncate(front.memfd, PAGE)
    address = front.create_bo_from_memfd(front.memfd, 0, PAGE, 0)
    target = front.bos[0]
    target._no_push = True
    backend.u.proxy.memset32(target._pa, 0, PAGE)
    backend.u.proxy.dc_civac(target._pa, PAGE)
    before = physical_read(backend, target._pa, 32)
    body = packed_cmdbuf(
        64, 64,
        color_attachment={"type": 0, "size": PAGE, "pointer": address},
    )
    storage = ctypes.create_string_buffer(body)
    args = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))
    saved_registration = backend.register_runtime_pair
    saved_queue_pair = backend.forced_queue_pair
    saved_channel_pair = backend.forced_channel_pair
    saved_descriptor_pair = backend.forced_descriptor_pair
    saved_descriptor_context = backend.forced_descriptor_context
    saved_optional_ordinal = backend.forced_optional_ordinal_base
    saved_reuse = backend.reuse_queue_items
    backend.register_runtime_pair = False
    backend.forced_queue_pair = 3
    backend.forced_channel_pair = 2
    backend.forced_descriptor_pair = 3
    backend.forced_descriptor_context = 2
    backend.forced_optional_ordinal_base = optional_ordinal
    backend.reuse_queue_items = False
    try:
        result = front.submit(front.memfd, args)
    finally:
        backend.register_runtime_pair = saved_registration
        backend.forced_queue_pair = saved_queue_pair
        backend.forced_channel_pair = saved_channel_pair
        backend.forced_descriptor_pair = saved_descriptor_pair
        backend.forced_descriptor_context = saved_descriptor_context
        backend.forced_optional_ordinal_base = saved_optional_ordinal
        backend.reuse_queue_items = saved_reuse
    after = physical_read(backend, target._pa, 32)
    if after == before:
        raise RuntimeError(
            "class-2 activation render retired without physical output")
    print(
        "COMPUTE class-2 activation render result=%r target=%#x physically changed" %
        (result, address),
        flush=True,
    )


def install_channel_control_record(backend, index, label):
    """Install one fresh host-owned channel-control destination record."""
    address = (backend.CHANNEL_CONTROL_BASE
               + int(index) * backend.CHANNEL_CONTROL_STRIDE)
    body = bytearray(backend.CHANNEL_CONTROL_STRIDE)
    for offset, value in backend.CHANNEL_CONTROL_FRESH_WORDS:
        struct.pack_into("<Q", body, offset, value)
    backend._write_dva(address, body)
    backend._clean_dva_range(address, backend.CHANNEL_CONTROL_STRIDE)
    backend.u.inst("dsb sy")
    if backend._read_dva(address, len(body)) != bytes(body):
        raise RuntimeError(
            "%s channel-control record %d did not read back" %
            (label, index))
    print(
        "COMPUTE installed fresh %s channel-control record %d at %#x" %
        (label, index, address),
        flush=True,
    )


def install_cl2_channel_record(backend):
    """Install the fresh channel record named by native CL2 optional items."""
    index = ((CHANNEL_CONTROL - backend.CHANNEL_CONTROL_BASE)
             // backend.CHANNEL_CONTROL_STRIDE)
    install_channel_control_record(backend, index, "CL2")


def map_operand_pages(backend, space):
    """Construct the complete native context-3 operand namespace."""
    count = compute.COMPUTE_OPERAND_TABLE_ENTRIES
    buffer_size = compute.COMPUTE_OPERAND_BUFFER_SIZE
    addresses = [
        OPERAND_BUFFER_BASE
        + index * compute.COMPUTE_OPERAND_BUFFER_STRIDE
        for index in range(count)
    ]

    # Context 3 starts as a deep clone of context 1. Native context 3 leaves
    # the 0x8000 stride tails between tranches absent, so clear the complete
    # namespace before installing its sparse owned mappings.
    namespace_end = addresses[-1] + buffer_size
    space.uat.iounmap(
        space.context,
        OPERAND_PAGE_LIST_BASE,
        namespace_end - OPERAND_PAGE_LIST_BASE,
    )

    # Keep the native virtual gaps, but allocate and clear the backing in one
    # operation so the exact lifecycle reaches its kick within 180 seconds.
    layout = [
        (OPERAND_PAGE_LIST_BASE, OPERAND_PAGE_LIST_REGION_SIZE,
         "operand_page_list_region"),
        (CLIENT_STATE, OPERAND_TABLE_REGION_SIZE, "operand_table_region"),
        (CLIENT_STATE_ZERO, CLIENT_STATE_REGION_SIZE, "client_state_region"),
    ]
    layout.extend(
        (address, buffer_size, "operand_tranche_%02d" % index)
        for index, address in enumerate(addresses)
    )
    total_size = sum(size for _address, size, _name in layout)
    backing = backend.u.memalign(PAGE, total_size)
    backend.u.proxy.memset32(backing, 0, total_size)
    backend.u.proxy.dc_civac(backing, total_size)

    flags = {
        "AttrIndex": MemoryAttr.Shared,
        "AP": 2,
        "nG": 1,
        "UXN": 1,
        "OS": 1,
    }
    mappings = {}
    offset = 0
    for address, size, name in layout:
        pa = backing + offset
        space.uat.iomap_at(space.context, address, pa, size, **flags)
        space.objects.append({
            "name": name,
            "va": address,
            "pa": pa,
            "size": size,
            "map_va": address,
            "map_pa": pa,
            "map_size": size,
            "flags": dict(flags),
        })
        mappings[name] = (address, pa)
        offset += size
    if offset != total_size:
        raise RuntimeError("batched operand backing size accounting failed")

    page_lists = mappings["operand_page_list_region"]
    table_region = mappings["operand_table_region"]
    state_region = mappings["client_state_region"]

    space.write(
        page_lists[1],
        compute.build_compute_operand_page_lists(
            OPERAND_BUFFER_BASE, entries=count))
    space.write(
        table_region[1],
        compute.build_compute_operand_table(
            OPERAND_BUFFER_BASE, entries=count))
    space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 3 << 48)
    backend.u.inst("dsb sy")

    for index, address in enumerate(addresses):
        translated = space.uat.iotranslate(
            space.context, address, buffer_size)
        covered = sum(length for pa, length in translated if pa is not None)
        if (not translated or any(pa is None for pa, _length in translated)
                or covered != buffer_size):
            raise RuntimeError(
                "operand tranche %d DVA %#x+%#x is not fully mapped: %r" %
                (index, address, buffer_size, translated))
        pte = space.uat.ioperm(space.context, address)
        if ((int(pte) >> 2) & 7) != int(MemoryAttr.Shared):
            raise RuntimeError(
                "operand tranche %d has non-shared PTE %#x" %
                (index, int(pte)))
        owners = []
        for obj in space.objects:
            obj_address = int(obj.get("map_va", obj["va"]))
            obj_size = int(obj.get("map_size", obj["size"]))
            if address < obj_address + obj_size and obj_address < address + buffer_size:
                owners.append(obj["name"])
        print(
            "COMPUTE operand tranche[%d] constructed %#x+%#x in %d PA run(s), "
            "pte=%#x owners=%s" % (
                index, address, buffer_size, len(translated), int(pte),
                ",".join(sorted(set(owners))) if owners else "untracked"),
            flush=True,
        )
    return {
        "operand_page_lists": page_lists,
        "operand_table": table_region,
        "client_state": state_region,
    }


def compute_registers(
        dispatch_identity=DISPATCH_IDENTITY, register_gate=2,
        resource=RESOURCE, cdm=CDM, robustness=ROBUSTNESS):
    return [
        (0x1A510, resource),
        (0x1A420, cdm),
        (0x1A4D0, resource + 0x1480),
        (0x1A4D8, resource + 0x1488),
        (0x1A4E0, resource + 0x1490),
        (0x1A4E8, resource + 0x1498),
        (0x1A440, 0x0000000154024201),
        (0x1A458, 0x0000000010C08860),
        (0x101D9, 0x1C),
        (0x1A089, 0),
        (0x1A091, 0),
        (0x1A059, 0),
        (0x1A061, 0),
        (0x1A0B9, 0),
        (0x1A0C1, 0),
        (0x101D1, 0),
        (0x0D479, 0),
        (0x1A0E9, 8),
        (0x107A1, 0xFF0000),
        (0x0A599, 0x0000013200400020),
        (0x0D411, 0x0000000200000001),
        (0x1A540, dispatch_identity),
        (0x014A9, dispatch_identity),
        (0x0A351, dispatch_identity),
        (0x10201, REGISTER_LIFECYCLE),
        (0x10428, REGISTER_LIFECYCLE),
        (0x14028, register_gate),
        (0x14070, robustness | 1),
        (0x10229, SCRATCH + 0xA800),
        (0x140A8, SCRATCH + 0xB000),
        (0x10099, SCRATCH + 0x1405),
        (0x10091, SCRATCH + 0xA400),
        (0x0A5C1, CLIENT_STATE_ZERO + 5),
        (0x0A5C9, SCRATCH + 0x1000),
        (0x1A440, 0x0000000154024209),
        (0x0A599, 0x0000006000400020),
    ]


def build_client_graph(backend, input_a_dependency=None):
    space = create_compute_context3_space(backend)
    namespace = map_operand_pages(backend, space)
    objects = {}
    for address, size, name, read_only in (
        (RESOURCE, RESOURCE_SIZE, "resource", False),
        (CDM, PAGE, "cdm", True),
        (BUFFER_A, PAGE, "input_a", False),
        (BUFFER_B, PAGE, "input_b", False),
        (BUFFER_OUT, PAGE, "output", False),
        (SHADER, PAGE, "shader", False),
        (ROBUSTNESS, PAGE, "robustness", False),
    ):
        objects[name] = map_client(
            backend, address, size, name, read_only=read_only,
            space=space,
        )
    objects["operand_table"] = namespace["operand_table"]
    objects["client_state_zero"] = (
        CLIENT_STATE_ZERO, namespace["client_state"][1])
    objects["scratch"] = (
        SCRATCH,
        namespace["client_state"][1] + SCRATCH - CLIENT_STATE_ZERO)

    if input_a_dependency is None:
        values_a = [1000.0 + index * 0.5 for index in range(64)]
        input_a_dva = BUFFER_A
    else:
        values_a = list(input_a_dependency["values"])
        if len(values_a) != 64:
            raise ValueError("compute dependency must contain 64 floats")
        source_pa = int(input_a_dependency["source_pa"])
        source_offset = int(input_a_dependency["source_offset"])
        if source_pa & (PAGE - 1):
            raise ValueError("compute dependency PA is not page aligned")
        if source_offset < 0 or source_offset + 256 > PAGE:
            raise ValueError("compute dependency window crosses its page")
        flags = {
            "AttrIndex": MemoryAttr.Shared,
            "AP": 2,
            "nG": 1,
            "UXN": 1,
            "OS": 1,
        }
        space.uat.iomap_at(
            space.context, RENDER_DEPENDENCY_ALIAS, source_pa, PAGE, **flags)
        space.objects.append({
            "name": "render_dependency",
            "va": RENDER_DEPENDENCY_ALIAS,
            "pa": source_pa,
            "size": PAGE,
            "map_va": RENDER_DEPENDENCY_ALIAS,
            "map_pa": source_pa,
            "map_size": PAGE,
            "flags": dict(flags),
        })
        input_a_dva = RENDER_DEPENDENCY_ALIAS + source_offset
    values_b = [1100.0 + index * 0.5 for index in range(64)]
    expected = [left + right for left, right in zip(values_a, values_b)]
    if input_a_dependency is None:
        space.write(objects["input_a"][1], struct.pack("<64f", *values_a))
    space.write(objects["input_b"][1], struct.pack("<64f", *values_b))
    space.write(objects["shader"][1], ADD3_SHADER)
    space.write(objects["client_state_zero"][1], bytes(PAGE))
    space.write(
        objects["operand_table"][1],
        compute.build_compute_operand_table(OPERAND_BUFFER_BASE),
    )
    space.write(
        objects["resource"][1],
        compute.build_buffer_resource_table(
            (input_a_dva, BUFFER_B, BUFFER_OUT), size=RESOURCE_SIZE),
    )
    stream = compute.build_cdm_stream((
        compute.build_direct_dispatch(
            SHADER, grid=(64, 1, 1), threadgroup=(32, 1, 1)),
    ))
    space.write(objects["cdm"][1], stream)
    space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 3 << 48)
    backend.u.inst("dsb sy")
    return objects, expected, CDM + len(stream) - 4, space


def build_firmware_graph(
        backend, cdm_terminator, reuse_scheduler_lifecycle=False,
        descriptor_override=None, submission_profile=None,
        registers_override=None):
    profile = {
        "grid_index": GRID,
        "queue_uuid": QUEUE_UUID,
        "dispatch_identity": DISPATCH_IDENTITY,
        "register_gate": 2,
        "submission_ordinal": SUBMISSION_ORDINAL,
        "optional_field_46": 2,
        "optional_field_56": 4,
        "shared_support_word_08": 2,
        "queue_context_word_220": 0xFFFF080400000001,
    }
    if submission_profile is not None:
        profile.update(submission_profile)
    grid_index = int(profile["grid_index"])
    queue_uuid = int(profile["queue_uuid"])
    for address, size in (
        (QUEUE_POINTERS, 0x80),
        (ITEM_RING, PAGE),
        (QUEUE, g17p.QUEUE_RECORD_STRIDE),
        (OPTIONAL, compute.COMPUTE_OPTIONAL_SIZE),
        (EVENT, EVENT_RECORD_SIZE),
        (SCHEDULER, 0x100),
        (SCHEDULER_SLOT, 0x40),
        (JOB_LIST, 0x60),
        (SHARED_SUPPORT, PAGE),
        (SHARED_STATE, PAGE),
        (SUPPORT_STATE, PAGE),
        (ZERO_PAGE, PAGE),
        (DISPATCH_A, 8),
        (DISPATCH_B, 8),
        (STATUS_A, 8),
        (STATUS_B, 8),
    ):
        map_firmware(backend, address, size)
    alias_firmware(backend, DESCRIPTOR, DESCRIPTOR_LOW,
                   compute.COMPUTE_DESCRIPTOR_SIZE)
    alias_firmware(backend, QUEUE_CONTEXT_HIGH, QUEUE_CONTEXT_LOW,
                   compute.COMPUTE_QUEUE_CONTEXT_SIZE)

    backend._write_dva(QUEUE_POINTERS, g17p.build_queue_pointers())
    backend._write_dva(QUEUE_POINTERS + 0x60, struct.pack("<I", 0x500))
    backend._write_dva(ITEM_RING, bytes(PAGE))
    for offset in range(0, 0x60, g17p.JOB_LIST_SIZE):
        address = JOB_LIST + offset
        backend._write_dva(address, g17p.build_job_list(address))

    queue = bytearray(g17p.build_queue_record(
        pointers_addr=QUEUE_POINTERS,
        ring_addr=ITEM_RING,
        job_list_addr=JOB_LIST,
        context_addr=CHANNEL_CONTROL,
        uuid=queue_uuid,
        priority=2,
        prio5=2,
        unk_2c=2,
        unk_38=0,
        sentinel_size=2,
    ))
    backend._write_dva(QUEUE, queue)

    if reuse_scheduler_lifecycle:
        scheduler_page = coherent_dva_read(backend, SCHEDULER_PAGE, 0x200)
        if struct.unpack_from("<Q", scheduler_page, 0)[0] != SHARED_STATE:
            raise RuntimeError(
                "pair-2 lifecycle did not publish scheduler page %#x" %
                SCHEDULER_PAGE)
        expected_scheduler = compute.build_compute_scheduler_record(
            SCHEDULER_SLOT)
        if scheduler_page[0x100:0x200] != expected_scheduler:
            raise RuntimeError(
                "pair-2 lifecycle scheduler record %#x is not native-ready" %
                SCHEDULER)
        state = coherent_dva_read(backend, SHARED_STATE, 8)
        if state != struct.pack("<Q", 1 << 32):
            raise RuntimeError(
                "pair-2 lifecycle scheduler state %#x is %s, expected %s" %
                (SHARED_STATE, state.hex(), struct.pack("<Q", 1 << 32).hex()))
        print(
            "COMPUTE reusing lifecycle-produced scheduler page %#x slot %#x" %
            (SCHEDULER_PAGE, SCHEDULER_SLOT),
            flush=True,
        )
    else:
        scheduler_page = bytearray(PAGE)
        struct.pack_into("<Q", scheduler_page, 0, SHARED_STATE)
        scheduler_page[0x100:0x200] = (
            compute.build_compute_scheduler_record(SCHEDULER_SLOT))
        if os.getenv("G17P_COMPUTE_FULL_SCHEDULER_PAGE") == "1":
            for index in range(2, 36):
                struct.pack_into(
                    "<Q", scheduler_page, index * 0x100,
                    SHARED_STATE + index * 4)
            print(
                "COMPUTE populated all 36 native scheduler pointer records",
                flush=True,
            )
        backend._write_dva(SCHEDULER_PAGE, scheduler_page)
        state = bytearray(PAGE)
        struct.pack_into("<I", state, SCHEDULER_SLOT - SHARED_STATE, 1)
        backend._write_dva(SHARED_STATE, state)
    backend._write_dva(SUPPORT_STATE, compute.build_compute_shared_state())
    backend._write_dva(
        SHARED_SUPPORT,
        compute.build_compute_shared_support(
            CLIENT_STATE, SUPPORT_STATE,
            word_08=profile["shared_support_word_08"],
            word_10=SUPPORT_WORD_10,
            header=SHARED_SUPPORT_HEADER,
            resource_class=0x15, cursor=0xA8, final_kind=2,
        ),
    )
    backend._write_dva(ZERO_PAGE, bytes(PAGE))
    backend._write_dva(
        STATUS_A, struct.pack("<Q", STATUS_A_VALUE))
    backend._write_dva(
        STATUS_B, struct.pack("<Q", STATUS_B_VALUE))
    backend._write_dva(
        QUEUE_CONTEXT_HIGH,
        compute.build_compute_queue_context(
            DESCRIPTOR, QUEUE, grid_index,
            flags_200=0x1000000000000000,
            word_220=profile["queue_context_word_220"],
            word_330=0,
            word_338=8,
            word_350=QUEUE_CONTEXT_WORD_350,
            word_358=QUEUE_CONTEXT_WORD_358,
        ),
    )
    backend._write_dva(
        OPTIONAL,
        compute.build_compute_optional(
            QUEUE_CONTEXT_LOW, QUEUE_CONTEXT_HIGH,
            grid_index=grid_index,
            submission_ordinal=profile["submission_ordinal"],
            shared_control=SHARED_SUPPORT,
            channel_control=CHANNEL_CONTROL,
            uuid=queue_uuid, field_46=profile["optional_field_46"],
            field_1e=2, field_32=3,
            field_56=profile["optional_field_56"], field_5e=2,
        ),
    )
    backend._write_dva(
        EVENT,
        compute.build_compute_event(
            1, grid_index, counter_low=2)[:EVENT_RECORD_SIZE])
    descriptor = (
        bytes(descriptor_override)
        if descriptor_override is not None
        else compute.build_compute_descriptor(
            (registers_override if registers_override is not None
             else compute_registers(
                 profile["dispatch_identity"], profile["register_gate"])),
            scheduler_record=SCHEDULER,
            low_alias=DESCRIPTOR_LOW, cdm_terminator=cdm_terminator,
            submit_sequence=SUBMIT_SEQUENCE,
            context_id=3,
            grid_index=grid_index,
            dispatch_a=DISPATCH_A, dispatch_b=DISPATCH_B,
            status_a=STATUS_A, status_b=STATUS_B,
            zero_page=ZERO_PAGE, shared_control=SHARED_SUPPORT,
            protection_index=1,
            support_control=0xE0A00001,
            support_flags=0,
        )
    )
    if len(descriptor) != compute.COMPUTE_DESCRIPTOR_SIZE:
        raise ValueError(
            "compute descriptor override has size %#x, expected %#x" %
            (len(descriptor), compute.COMPUTE_DESCRIPTOR_SIZE))
    backend._write_dva(DESCRIPTOR, descriptor)

    # The optional's low and high queue-context pointers are not aliases in
    # any output-positive capture.  The low pointer walks the retained client
    # root and names a blank page; only the firmware-high page is populated.
    client_low = backend.space.uat.iotranslate(
        backend.space.context, QUEUE_CONTEXT_LOW, PAGE)
    firmware_high = backend.space.uat.iotranslate_root(
        backend.firmware_high_root, QUEUE_CONTEXT_HIGH, PAGE)
    if (client_low and client_low[0][0] is not None
            and firmware_high and firmware_high[0][0] is not None):
        low_pa = client_low[0][0]
        high_pa = firmware_high[0][0]
        low_blank = not any(physical_read(backend, low_pa, PAGE))
        print(
            "COMPUTE queue-context views: client-low PA %#x %s; "
            "firmware-high PA %#x; distinct=%s" % (
                low_pa, "blank" if low_blank else "nonblank", high_pa,
                low_pa != high_pa),
            flush=True,
        )

    backend.space.flush()
    backend.u.inst("dsb osh; tlbi vmalle1os; dsb osh; isb")
    clean_ranges = [
        (QUEUE_POINTERS, 0x80), (ITEM_RING, PAGE),
        (QUEUE, g17p.QUEUE_RECORD_STRIDE),
        (DESCRIPTOR, compute.COMPUTE_DESCRIPTOR_SIZE),
        (OPTIONAL, compute.COMPUTE_OPTIONAL_SIZE),
        (EVENT, EVENT_RECORD_SIZE),
        (JOB_LIST, 0x60), (SHARED_SUPPORT, PAGE),
        (SUPPORT_STATE, PAGE),
        (QUEUE_CONTEXT_HIGH, PAGE),
        (STATUS_A, 8),
        (STATUS_B, 8),
    ]
    if not reuse_scheduler_lifecycle:
        clean_ranges.extend(((SCHEDULER_PAGE, PAGE), (SHARED_STATE, PAGE)))
    for address, size in clean_ranges:
        backend._clean_dva_range(address, size)
    backend.u.inst("dsb sy")
    return G17PQueue(backend._read_dva, QUEUE, grid_index)


def trigger_submission(front, backend, trigger, channel_name):
    if trigger == "work":
        backend.submitter.notify(grid_index_for(channel_name))
        return
    if trigger != "control-start":
        raise ValueError("unknown compute trigger %r" % trigger)
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("control-start compute requires in-process cold boot")
    message = runtime["doorbell_message"]
    for asc in runtime["ascs"]:
        asc.db.send(message(
            TYPE=g17p.MSG_CONTROL_START,
            CHANNEL=g17p.CONTROL_START_CHANNEL,
        ))
    print(
        "COMPUTE sent control-start to %d firmware instances with CL_0 pending" %
        len(runtime["ascs"]),
        flush=True,
    )


def _finite_render_dependency(render):
    before = render["before"]
    after = render["after"]
    for offset in range(0, PAGE - 256 + 1, 4):
        body = after[offset:offset + 256]
        values = struct.unpack("<64f", body)
        if (body != before[offset:offset + 256]
                and all(math.isfinite(value) for value in values)):
            return {
                "values": list(values),
                "source_pa": render["target_pa"],
                "source_offset": offset,
            }
    raise RuntimeError(
        "render target has no changed finite 64-float dependency window")


def run_probe(front, backend, trigger="work", render_dependency=False):
    signal.signal(signal.SIGALRM, _timeout)
    try:
        drain_boot_group(front, backend)
        runtime = front.g17p_runtime
        if (runtime is None or
                "register_runtime_pair" not in runtime or
                "register_compute_control" not in runtime or
                "advance_runtime_ticks" not in runtime or
                "announce_runtime_1b_grid" not in runtime):
            raise RuntimeError("cold boot exposes no runtime registrar")
        cadence = run_render_cadence(front, backend, runtime)
        render = cadence["dependency_render"] if render_dependency else None
        input_a_dependency = (
            _finite_render_dependency(render) if render is not None else None)
        if input_a_dependency is not None:
            backend.u.proxy.dc_civac(render["target_pa"], PAGE)
            if not all(snapshot["signaled"]
                       for snapshot in render["fence_snapshots"].values()):
                raise RuntimeError(
                    "render output changed without both queue fences signaling")
        objects, expected, terminator, client_space = build_client_graph(
            backend, input_a_dependency=input_a_dependency)
        queue = build_firmware_graph(backend, terminator)
        prepare_context2_activation(backend)
        install_native_compute_primary_records(backend)
        install_cl2_channel_record(backend)
        control_objects = install_final_26_6_control_objects(backend)

        # Final 26.6 advances the opening class-1 object through this exact
        # primary-control cadence before it admits CL2.  In particular, the
        # compute transition is class 3, not the beta-era class 2 path.
        if (not backend.runtime_pair_registered or
                backend.group_number != FINAL_26_6_RENDER_PREFIX_COUNT or
                backend.queue_pair_submissions.get(0) !=
                FINAL_26_6_RENDER_PREFIX_COUNT // 2 or
                backend.queue_pair_submissions.get(1) !=
                FINAL_26_6_RENDER_PREFIX_COUNT // 2):
            raise RuntimeError(
                "final-26.6 generated prefix did not reach 32 renders")
        runtime["advance_runtime_ticks"](33)
        runtime["announce_runtime_1b_grid"](
            "final-26.6 compute prefix 0x1b")
        runtime["announce_runtime_tick"](
            34, "final-26.6 compute prefix sequence 34",
            require_consumed=True, update_sequence=True)
        channel_after_runtime = coherent_dva_read(
            backend, backend.CHANNEL_CONTROL_BASE, 0x100)
        print(
            "COMPUTE pre-class1 channel-control=%s" %
            channel_after_runtime.hex(),
            flush=True,
        )
        if any(channel_after_runtime[0x80:0xc0]):
            raise RuntimeError(
                "context-2 channel-control record became nonzero before class 1")

        class1 = runtime["register_compute_control"](
            1, FINAL_26_6_CLASS1_SUPPORT, PRIMARY_CONTROL_OPERAND,
            slot_offset=0x440, context_word=1, count=0x20,
        )
        runtime["announce_runtime_tick"](
            36, "final-26.6 class-1 trailing sequence 36",
            context_word=1, require_consumed=True, update_sequence=True)
        channel_after_class1 = coherent_dva_read(
            backend, backend.CHANNEL_CONTROL_BASE, 0x100)

        # Native leaves context 2's +0x80 destination record zero at the
        # class-1 boundary and initializes it only before publishing class 3.
        install_channel_control_record(backend, 2, "context-2 activation")
        class3 = runtime["register_compute_control"](
            3, FINAL_26_6_CLASS3_SUPPORT, PRIMARY_CONTROL_OPERAND,
            slot_offset=0x5C0, context_word=2, count=0x28,
        )
        class3_tick = runtime["announce_runtime_tick"](
            38, "final-26.6 class-3 trailing sequence 38",
            context_word=2, require_consumed=True, update_sequence=True)
        class3["trailing_0x2e"] = class3_tick
        channel_after_class3 = coherent_dva_read(
            backend, backend.CHANNEL_CONTROL_BASE, 0x100)
        print(
            "COMPUTE final-26.6 control suffix retired: "
            "class1=%r class3=%r objects=%s" % (
                class1, class3, ",".join(sorted(control_objects))),
            flush=True,
        )

        entry = backend.channels.by_name("CL_2")
        if entry is None:
            raise RuntimeError("cold boot exposes no CL_2 channel")
        start = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, PROBE_TIMEOUT)
        backend._write_dva(
            SCHEDULER,
            compute.build_compute_scheduler_record(SCHEDULER_SLOT),
        )
        backend._clean_dva_range(SCHEDULER_PAGE, PAGE)
        backend.u.inst("dsb sy")

        published = backend.submitter.stage(
            entry, queue, (DESCRIPTOR, OPTIONAL, EVENT),
            group_number=1, slot=0, first_submit=True,
            kind="compute", announce=False,
        )
        for address, size in (
            (ITEM_RING, 0x18),
            (QUEUE_POINTERS, 0x80),
            (entry["ring_addr"], g17p.RING_SLOT_SIZE),
        ):
            backend._clean_dva_range(address, size)
        for address in entry["state_addrs"]:
            backend._clean_dva_range(address, 4)
        backend.u.inst("dsb sy")

        fence = G17PQueueFence(
            backend.submitter,
            entry,
            queue,
            published,
            name="first CL2 compute workload",
        )
        if fence.signaled():
            raise RuntimeError("compute fence signaled before its doorbell")

        output_pa = objects["output"][1]
        client_before = {
            "resource": physical_read(
                backend, objects["resource"][1], RESOURCE_SIZE),
            "input_a": physical_read(backend, objects["input_a"][1], PAGE),
            "input_b": physical_read(backend, objects["input_b"][1], PAGE),
            "output": physical_read(backend, output_pa, PAGE),
            "shader": physical_read(backend, objects["shader"][1], PAGE),
        }
        before = physical_read(backend, output_pa, 64 * 4)
        scheduler_before = coherent_dva_read(backend, SCHEDULER, 0x100)
        job_before = coherent_dva_read(backend, JOB_LIST, 0x18)
        channel_before = coherent_dva_read(
            backend, backend.CHANNEL_CONTROL_BASE, 0x100)
        dump_hardware_uat_slots(backend)
        trigger_submission(front, backend, trigger, "CL_2")

        deadline = time.monotonic() + COMPLETION_TIMEOUT
        after = before
        while time.monotonic() < deadline:
            after = physical_read(backend, output_pa, 64 * 4)
            if after != before:
                break
            time.sleep(0.0001)

        queue_after_kick = queue.indices()
        channel_after_kick = backend.channels.counters(entry)
        print(
            "COMPUTE post-kick queue=%s channel=%s output=%s" % (
                queue_after_kick, channel_after_kick,
                "changed" if after != before else "unchanged",
            ),
            flush=True,
        )
        print("COMPUTE scheduler class1=%s" % class1, flush=True)
        print("COMPUTE scheduler class3=%s" % class3, flush=True)
        print(
            "COMPUTE channel-control stages runtime=%s class1=%s class3=%s" % (
                channel_after_runtime.hex(), channel_after_class1.hex(),
                channel_after_class3.hex()),
            flush=True,
        )

        queue_state = queue.indices()
        channel_state = backend.channels.counters(entry)
        scheduler_after = coherent_dva_read(backend, SCHEDULER, 0x100)
        job_after = coherent_dva_read(backend, JOB_LIST, 0x18)
        channel_after = coherent_dva_read(
            backend, backend.CHANNEL_CONTROL_BASE, 0x100)
        for name, old in client_before.items():
            size = RESOURCE_SIZE if name == "resource" else PAGE
            new = physical_read(backend, objects[name][1], size)
            count, offsets = changed_offsets(old, new)
            print("COMPUTE client delta %s: %d bytes (%s)" % (
                name, count, offsets), flush=True)
        scheduler_changed = scheduler_after != scheduler_before
        job_changed = job_after != job_before
        elapsed = time.monotonic() - start
        print(
            "COMPUTE first-CL_2 elapsed=%.3fs queue=%s channel=%s "
            "scheduler=%s job_list=%s" % (
                elapsed, queue_state, channel_state,
                "changed" if scheduler_changed else "unchanged",
                "changed" if job_changed else "unchanged",
            ),
            flush=True,
        )
        print("COMPUTE scheduler delta: %s" % byte_delta(
            scheduler_before, scheduler_after), flush=True)
        print("COMPUTE job-list delta: %s" % byte_delta(
            job_before, job_after), flush=True)
        print("COMPUTE channel-control before=%s after=%s delta=%s" % (
            channel_before.hex(), channel_after.hex(),
            byte_delta(channel_before, channel_after)), flush=True)

        if after == before:
            print("COMPUTE OUTPUT: unchanged", flush=True)
            return 2
        fence.wait(timeout=COMPLETION_TIMEOUT, event_pump=backend.event_pump)
        fence_state = fence.snapshot()
        actual = list(struct.unpack("<64f", after))
        if actual != expected:
            mismatch = next(
                index for index, values in enumerate(zip(actual, expected))
                if values[0] != values[1])
            print(
                "COMPUTE OUTPUT: changed but wrong at %d: got %r expected %r" %
                (mismatch, actual[mismatch], expected[mismatch]),
                flush=True,
            )
            return 3
        print("COMPUTE OUTPUT: EXECUTED, 64/64 exact add3 results", flush=True)
        print("COMPUTE FENCE: %r" % fence_state, flush=True)
        if input_a_dependency is not None:
            print(
                "MIXED RENDER->COMPUTE PASS: render PA %#x offset %#x was "
                "visible to exact dependent add3; TA/3D and CL2 fences signaled" %
                (render["target_pa"], input_a_dependency["source_offset"]),
                flush=True,
            )
        return 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main(trigger="work"):
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute.py accepts no arguments")
    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        if front.g17p is None:
            raise RuntimeError("G17P backend did not initialize")
        return run_probe(front, front.g17p, trigger=trigger)


if __name__ == "__main__":
    raise SystemExit(main())
