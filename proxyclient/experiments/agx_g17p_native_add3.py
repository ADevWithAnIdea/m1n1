#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Field-build and publish the minimal output-positive G17P add3 graph.

The constants in this file are decoded firmware-ABI fields from a clean-room
hardware capture.  No capture is read at runtime and no captured page content
is copied.  Every mapped byte is emitted by a builder or explicitly zeroed.
"""

import hashlib
import json
import os
import struct
import time

from m1n1.agx import g17p, g17p_compute as compute
from m1n1.agx.g17p_backend import G17PQueue, G17PQueueFence
from m1n1.hw.uat import MemoryAttr
from g17p_add3_code import build_add3_code_image
from g17p_indirect_code import build_indirect_add3_preamble


PAGE = 0x4000
CONTEXT = 2
GRID = 4
INDIRECT_GRID = 2

OUTER_RING = 0xFFFFFC20C07A1DC0
WORK_DOORBELL_CHANNEL = 0x0A
QUEUE = 0xFFFFFC20C0000300
QUEUE_POINTERS = 0xFFFFFC200165A870
ITEM_RING = 0xFFFFFC20C08AA870
QUEUE_1 = 0xFFFFFC20C00003C0
QUEUE_PAIR_OBJECT_STRIDE = 0x2870
QUEUE_POINTERS_1 = 0xFFFFFC200166D0E0
ITEM_RING_1 = 0xFFFFFC20C08B50E0
QUEUE_2 = 0xFFFFFC20C0000540
QUEUE_POINTERS_2 = 0xFFFFFC20016BA870
ITEM_RING_2 = 0xFFFFFC20C0912870
QUEUE_3 = 0xFFFFFC20C0000600
QUEUE_POINTERS_3 = 0xFFFFFC20016BD0E0
ITEM_RING_3 = 0xFFFFFC20C09150E0
JOB_LIST_BASE = 0xFFFFFC2000000000
JOB_LIST = JOB_LIST_BASE + 0x18
JOB_LIST_1 = JOB_LIST_BASE + 0x48
CHANNEL_RECORD = 0xFFFFFC20C07B8040
CHANNEL_RECORD_1 = 0xFFFFFC20C07B80C0
DESCRIPTOR = 0xFFFFFC20C0358000
DESCRIPTOR_LOW = 0x7000340000
OPTIONAL = 0xFFFFFC20C0605E80
EVENT = 0xFFFFFC20C05EA200
OPTIONAL_1 = 0xFFFFFC20C0603E40
EVENT_1 = 0xFFFFFC20C05E96C0
OPTIONAL_2 = 0xFFFFFC20C0604EC0
EVENT_2 = 0xFFFFFC20C05E9C80
OPTIONAL_3 = 0xFFFFFC20C0604440
EVENT_3 = 0xFFFFFC20C05E98C0
DESCRIPTOR_STRIDE = 0x1040
DESCRIPTOR_RING_RECORDS = 240
SCHEDULER_RING_RECORDS = 36
OPTIONAL_STRIDE = 0xC0
EVENT_STRIDE = 0x40
RUNTIME_EVENT_BASE = 0xFFFFFC20C05E9600
DESCRIPTOR_BODY_SIZE = 0x1000
SCHEDULER_RECORD_STRIDE = 0x100
QUEUE_CONTEXT_LOW = 0x70004D8000
QUEUE_CONTEXT_HIGH = 0xFFFFFC2000278000
QUEUE_CONTEXT_LOW_1 = 0x7000500000
QUEUE_CONTEXT_HIGH_1 = 0xFFFFFC20002A0000
QUEUE_CONTEXT_LOW_2 = 0x7000550000
QUEUE_CONTEXT_HIGH_2 = 0xFFFFFC20002F0000
QUEUE_CONTEXT_LOW_3 = 0x7000580000
QUEUE_CONTEXT_HIGH_3 = 0xFFFFFC2000318000
SCHEDULER_PAGE = 0xFFFFFC20C0868000
SCHEDULER = SCHEDULER_PAGE + 0x100
SCHEDULER_1 = 0xFFFFFC20C0870200
SCHEDULER_2 = 0xFFFFFC20C0870300
SCHEDULER_3 = 0xFFFFFC20C08C8400
SCHEDULER_SLOT_3 = 0xFFFFFC2001680010
RUNTIME_SCHEDULER_POOL = 0xFFFFFC20C0B00000
RUNTIME_SCHEDULER_STATE = 0xFFFFFC2001800000
SHARED_STATE = 0xFFFFFC2001630000
SCHEDULER_SLOT = SHARED_STATE + 4
SHARED_SUPPORT = 0xFFFFFC20C0870000
SUPPORT_STATE = 0xFFFFFC2001638000
SCHEDULER_SLOT_1 = SUPPORT_STATE + 8
SCHEDULER_SLOT_2 = SUPPORT_STATE + 0xC
ZERO_PAGE = 0xFFFFFC2001640000
SHARED_SUPPORT_1 = 0xFFFFFC20C08D0000
SUPPORT_STATE_1 = 0xFFFFFC2001688000
ZERO_PAGE_1 = 0xFFFFFC2001698000
SHARED_SUPPORT_2 = 0xFFFFFC20C0908000
SUPPORT_STATE_2 = 0xFFFFFC20016A8000
ZERO_PAGE_2 = 0xFFFFFC20016C8000
SHARED_SUPPORT_3 = 0xFFFFFC20C0920000
SUPPORT_STATE_3 = 0xFFFFFC20016D0000
ZERO_PAGE_3 = 0xFFFFFC20016D8000
DISPATCH_A = 0xFFFFFC20001C8008
DISPATCH_B = 0xFFFFFC20C07C0008
STATUS_A = 0xFFFFFC2000024C68
STATUS_B = 0xFFFFFC2000024C70

RESOURCE = 0x100000F8000
RESOURCE_SIZE = 0xC000
CDM = 0x100000C8000
CDM_SIZE = 0x8000
SHADER = 0x100000A8000
SHADER_SIZE = 0x8000
INPUT_A = 0x10000030000
INPUT_B = 0x10000038000
OUTPUT = 0x10000040000
ROBUSTNESS = 0x1000018000
CODE_IMAGE = 0x10000000000
INPUT_POOL_BASE = 0x10002000000
OUTPUT_POOL_BASE = 0x10004000000
INDIRECT_ARGUMENT_BASE = 0x10005000000
INDIRECT_ARGUMENT_STRIDE = PAGE
INDIRECT_HELPER_CONSTANT = 0x10006000000
INDIRECT_HELPER_BINDING_BASE = 0x10007000000
INDIRECT_NATIVE_ARGUMENT_BASE = 0x10000040000
INDIRECT_NATIVE_HELPER_CONSTANT_PAGE = 0x10000048000
INDIRECT_NATIVE_HELPER_CONSTANT_OFFSET = 0x2500
INDIRECT_NATIVE_HELPER_BINDING_BASE = 0x100000A0000
INDIRECT_NATIVE_HELPER_BINDING_OFFSET = 0xB0
INDIRECT_NATIVE_SHADER = 0x100000B0000
INDIRECT_NATIVE_CDM = 0x100000D0000
INDIRECT_NATIVE_RESOURCE = 0x10000100000
INDIRECT_NATIVE_OUTPUT = 0x10000098000
INDIRECT_PUBLIC_BINDING_BASE = 0x10000080000
INDIRECT_PUBLIC_SHADER = 0x10000090000
INDIRECT_PUBLIC_CDM = 0x100000B0000
INDIRECT_PUBLIC_RESOURCE = 0x100000E0000
INPUT_POOL_WORKLOAD_STRIDE = 2 * PAGE
CLIENT_WORKLOAD_STRIDE = 0x78000
OUTPUT_WORKLOAD_STRIDE = 0xC8000
ROBUSTNESS_WORKLOAD_STRIDE = 0x8000

OPERAND_PAGE_LIST_BASE = 0x7000000000
OPERAND_PAGE_LIST_SIZE = 0x200000
OPERAND_TABLE = 0x7000208000
OPERAND_TABLE_SIZE = 0x10000
STATE_BASE = 0x7000220000
STATE_SIZE = 0x14000
OPERAND_BUFFER_BASE = 0x7000238000
OPERAND_BUFFER_WORKLOAD_STRIDE = (
    compute.COMPUTE_OPERAND_TABLE_ENTRIES
    * compute.COMPUTE_OPERAND_BUFFER_STRIDE
)
OPERAND_STATE_WORKLOAD_STRIDE = (
    OPERAND_BUFFER_BASE + OPERAND_BUFFER_WORKLOAD_STRIDE - STATE_BASE
)
NATIVE_CONTROL_TABLE_A = 0x70013A0000
INDIRECT_DISPATCH_IDENTITIES = (
    0x010001870200018C,
    0x0200021D0300023F,
)

# The output-positive native indirect pair shares one queue backing allocation.
# Command 1 occupies the retained ring entry and command 2 appends after it.
INDIRECT_FIRST_OPTIONAL = 0xFFFFFC20C06048C0
INDIRECT_FIRST_EVENT = 0xFFFFFC20C05E9980
INDIRECT_FIRST_SCHEDULER = 0xFFFFFC20C0828100
INDIRECT_FIRST_SCHEDULER_SLOT = 0xFFFFFC2001600004
INDIRECT_FIRST_ZERO_PAGE = 0xFFFFFC2001690000
INDIRECT_SECOND_POINTERS = 0xFFFFFC200166A870
INDIRECT_SECOND_ITEM_RING = 0xFFFFFC20C08B2870
INDIRECT_SECOND_OPTIONAL = 0xFFFFFC20C0604980
INDIRECT_SECOND_EVENT = 0xFFFFFC20C05E99C0
INDIRECT_SECOND_SCHEDULER = 0xFFFFFC20C0828200
INDIRECT_SECOND_SCHEDULER_SLOT = 0xFFFFFC2001600008
INDIRECT_SECOND_ZERO_PAGE = 0xFFFFFC2001690040


def _indirect_first_addresses():
    spec = dict(_queue_addresses(0))
    spec.update({
        "pointers": INDIRECT_SECOND_POINTERS,
        "item_ring": INDIRECT_SECOND_ITEM_RING,
        "job_list": JOB_LIST_1,
        "channel_control": CHANNEL_RECORD_1,
        "grid": 4,
        "uuid": 0x14D,
        "optional": INDIRECT_FIRST_OPTIONAL,
        "event": INDIRECT_FIRST_EVENT,
        "scheduler": INDIRECT_FIRST_SCHEDULER,
        "scheduler_slot": INDIRECT_FIRST_SCHEDULER_SLOT,
        "scheduler_work_id": 0,
        "shared_support": SHARED_SUPPORT_1,
        "support_state": SUPPORT_STATE_1,
        "zero_page": INDIRECT_FIRST_ZERO_PAGE,
        "context_id": CONTEXT + 1,
        "dispatch_a": 0xFFFFFC20001C8010,
        "dispatch_b": 0xFFFFFC20C07C0010,
        "optional_submission": 0x2F,
        "optional_field_32": 3,
        "optional_field_46": 1,
        "optional_field_56": 2,
        "qctx_word_220": 0xFFFF080200000001,
        "qctx_word_338": 8,
        "native_indirect_first": True,
    })
    return spec


def _indirect_second_addresses():
    spec = dict(_queue_addresses(1))
    spec.update({
        "queue": QUEUE,
        "pointers": INDIRECT_SECOND_POINTERS,
        "item_ring": INDIRECT_SECOND_ITEM_RING,
        "job_list": JOB_LIST_1,
        "context_low": QUEUE_CONTEXT_LOW,
        "context_high": QUEUE_CONTEXT_HIGH,
        "channel_control": CHANNEL_RECORD_1,
        "grid": 4,
        "uuid": 0x14D,
        "optional": INDIRECT_SECOND_OPTIONAL,
        "event": INDIRECT_SECOND_EVENT,
        "scheduler": INDIRECT_SECOND_SCHEDULER,
        "scheduler_slot": INDIRECT_SECOND_SCHEDULER_SLOT,
        "scheduler_work_id": 1,
        "shared_support": SHARED_SUPPORT_1,
        "support_state": SUPPORT_STATE_1,
        "zero_page": INDIRECT_SECOND_ZERO_PAGE,
        "dispatch_a": 0xFFFFFC20001C8010,
        "dispatch_b": 0xFFFFFC20C07C0010,
        "status_a": STATUS_A,
        "status_b": STATUS_B,
        "optional_submission": 0x30,
        "optional_field_32": 3,
        "optional_field_46": 1,
        "optional_field_56": 2,
        "native_indirect_second": True,
    })
    return spec


def _indirect_runtime_addresses(ordinal):
    """Return one command-local allocation from the retained indirect pair."""
    ordinal = int(ordinal)
    if ordinal < 1:
        raise ValueError("indirect runtime ordinals start at one")
    spec = _indirect_second_addresses()
    spec.update({
        "descriptor": DESCRIPTOR + ordinal * DESCRIPTOR_STRIDE,
        "descriptor_low": DESCRIPTOR_LOW + ordinal * DESCRIPTOR_STRIDE,
        "optional": INDIRECT_FIRST_OPTIONAL + ordinal * OPTIONAL_STRIDE,
        "event": INDIRECT_FIRST_EVENT + ordinal * EVENT_STRIDE,
        "scheduler": (
            INDIRECT_FIRST_SCHEDULER + ordinal * SCHEDULER_RECORD_STRIDE),
        "scheduler_slot": INDIRECT_FIRST_SCHEDULER_SLOT + ordinal * 4,
        "scheduler_work_id": ordinal,
        "zero_page": INDIRECT_FIRST_ZERO_PAGE + ordinal * 0x40,
        "status_a": STATUS_A + ordinal * 0x10,
        "status_b": STATUS_B + ordinal * 0x10,
        "optional_submission": 0x2F + ordinal,
    })
    return spec

NATIVE_ADD3_SHADER = bytes.fromhex(
    "2ca0020012087c003c80020004000000"
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


def build_add3_preamble(shader_dva, usc_exec_base=None):
    """Relocate the authored add3 launch header to its USC code location.

    Native source graphs retain the original USC aperture and can use the
    absolute-DVA delta.  Modern UAPI callers choose ``usc_exec_base`` per
    queue; their compact chunk field is relative to that aperture instead.
    """
    shader_dva = int(shader_dva)
    body = bytearray(NATIVE_ADD3_SHADER)
    if usc_exec_base is None:
        capture_chunk = SHADER // 0x2000
        target_chunk = shader_dva // 0x2000
    else:
        usc_exec_base = int(usc_exec_base)
        capture_chunk = (SHADER - CODE_IMAGE) // 0x2000
        target_chunk = (shader_dva - usc_exec_base) // 0x2000
    chunk_field = struct.unpack_from("<H", body, 6)[0]
    chunk_field += target_chunk - capture_chunk
    if not 0 <= chunk_field <= 0xFFFF:
        raise ValueError("add3 preamble relocation exceeds its 16-bit field")
    struct.pack_into("<H", body, 6, chunk_field)

    # The first word carries the launch header's byte offset within its
    # 0x400-byte block in bits 15:6. Native indirect dispatch places a second
    # header at +0x100, changing 0xa02c to 0xe02c.
    capture_offset = SHADER & 0x3FF
    target_offset = shader_dva & 0x3FF
    first = struct.unpack_from("<H", body, 0)[0]
    first = (first + ((target_offset - capture_offset) << 6)) & 0xFFFF
    struct.pack_into("<H", body, 0, first)
    return bytes(body)


REGISTERS = (
    (0x1A510, RESOURCE),
    (0x1A420, CDM),
    (0x1A4D0, RESOURCE + 0x1480),
    (0x1A4D8, RESOURCE + 0x1488),
    (0x1A4E0, RESOURCE + 0x1490),
    (0x1A4E8, RESOURCE + 0x1498),
    (0x1A440, 0x154024201),
    (0x1A458, 0x10C08860),
    (0x101D9, 0x1C),
    (0x1A089, 0), (0x1A091, 0),
    (0x1A059, 0), (0x1A061, 0),
    (0x1A0B9, 0), (0x1A0C1, 0),
    (0x101D1, 0), (0x0D479, 0),
    (0x1A0E9, 8),
    (0x107A1, 0xFF0000),
    (0x0A599, 0x13200400020),
    (0x0D411, 0x200000001),
    (0x1A540, 0x010001D7020001DC),
    (0x014A9, 0x010001D7020001DC),
    (0x0A351, 0x010001D7020001DC),
    (0x10201, 0x200),
    (0x10428, 0x200),
    (0x14028, 1),
    (0x14070, ROBUSTNESS | 1),
    (0x10229, 0x7000232800),
    (0x140A8, 0x7000233000),
    (0x10099, 0x7000229405),
    (0x10091, 0x7000232400),
    (0x0A5C1, 0x7000220005),
    (0x0A5C9, 0x7000229000),
    (0x1A440, 0x154024209),
    (0x0A599, 0x6000400020),
)


def _work_ordinal(ordinal):
    return int(ordinal)


def _registers_for_workload(ordinal, metadata_ordinal=None, command_slot=None,
                            indirect_dispatch=False, resource_base=RESOURCE,
                            cdm_base=CDM):
    """Advance the measured three-command compute register lifecycle."""
    ordinal = int(ordinal)
    metadata_ordinal = (
        ordinal if metadata_ordinal is None else int(metadata_ordinal))
    if ordinal < 0:
        raise ValueError("compute workload ordinal must be non-negative")
    command_slot = ordinal if command_slot is None else int(command_slot)
    if command_slot < 0:
        raise ValueError("compute command slot must be non-negative")
    operand_slot = min(command_slot, 1)
    work_ordinal = _work_ordinal(ordinal)
    context_id = CONTEXT if ordinal == 0 else CONTEXT + 1
    measured_identities = (
        0x010001D7020001DC,
        0x0200021C03000245,
        0x020002500300029C,
        0x0200020803000247,
    )
    if indirect_dispatch:
        if metadata_ordinal < len(INDIRECT_DISPATCH_IDENTITIES):
            dispatch_identity = INDIRECT_DISPATCH_IDENTITIES[metadata_ordinal]
        else:
            # Once the retained context-3 pair is established, use the same
            # packed allocator cadence measured for later direct commands:
            # +2 in the high u32 identity and +1 in the low u32 identity.
            step = metadata_ordinal - 1
            high = 0x0200021D + step * 2
            low = 0x0300023F + step
            dispatch_identity = (high << 32) | low
    elif metadata_ordinal < len(measured_identities):
        dispatch_identity = measured_identities[metadata_ordinal]
    else:
        # Native rollover captures advance this packed identity by +2/+1 in
        # its high/low u32 halves for each later queue item.
        step = metadata_ordinal - (len(measured_identities) - 1)
        high = 0x02000208 + step * 2
        low = 0x03000247 + step
        dispatch_identity = (high << 32) | low
    client_step = command_slot * CLIENT_WORKLOAD_STRIDE
    operand_step = operand_slot * OPERAND_STATE_WORKLOAD_STRIDE
    replacements = {
        0x1A510: int(resource_base) + client_step,
        0x1A420: int(cdm_base) + client_step,
        0x1A4D0: int(resource_base) + client_step + 0x1480,
        0x1A4D8: int(resource_base) + client_step + 0x1488,
        0x1A4E0: int(resource_base) + client_step + 0x1490,
        0x1A4E8: int(resource_base) + client_step + 0x1498,
        0x1A540: dispatch_identity,
        0x014A9: dispatch_identity,
        0x0A351: dispatch_identity,
        0x10201: (context_id << 8) | work_ordinal,
        0x10428: (context_id << 8) | work_ordinal,
        0x14070: (
            ROBUSTNESS + operand_slot * ROBUSTNESS_WORKLOAD_STRIDE) | 1,
        0x10229: 0x7000232800 + operand_step,
        0x140A8: 0x7000233000 + operand_step,
        0x10099: 0x7000229405 + operand_step,
        0x10091: 0x7000232400 + operand_step,
        0x0A5C1: 0x7000220005 + operand_step,
        0x0A5C9: 0x7000229000 + operand_step,
    }
    if ordinal >= 1:
        replacements.update({
            0x14028: 1 if metadata_ordinal == 3 else 0,
        })
    if indirect_dispatch:
        # Native indirect commands allocate 0x40-byte submission slots within
        # one robustness/state page.  Command 2 also enables the adjacent
        # execution gate in register 0x14028.
        replacements.update({
            0x14028: 1 if metadata_ordinal >= 1 else 0,
            0x14070: (ROBUSTNESS + metadata_ordinal * 0x40) | 1,
        })
    return tuple(
        (number, replacements.get(number, value))
        for number, value in REGISTERS
    )


def _queue_slot(ordinal, fresh_command3_style=False):
    ordinal = int(ordinal)
    if ordinal < 0:
        raise ValueError("compute queue ordinal must be non-negative")
    if ordinal == 0:
        return 0
    if fresh_command3_style and ordinal >= 3:
        return 3
    return 1 if ordinal & 1 else 2


def _queue_addresses(slot):
    if int(slot) == 0:
        return {
            "queue": QUEUE,
            "pointers": QUEUE_POINTERS,
            "item_ring": ITEM_RING,
            "job_list": JOB_LIST,
            "context_low": QUEUE_CONTEXT_LOW,
            "context_high": QUEUE_CONTEXT_HIGH,
            "channel_control": CHANNEL_RECORD,
            "grid": GRID,
            "uuid": 0x170,
            "descriptor": DESCRIPTOR,
            "descriptor_low": DESCRIPTOR_LOW,
            "optional": OPTIONAL,
            "event": EVENT,
            "scheduler": SCHEDULER,
            "scheduler_slot": SCHEDULER_SLOT,
            "scheduler_work_id": 0,
            "shared_support": SHARED_SUPPORT,
            "support_state": SUPPORT_STATE,
            "zero_page": ZERO_PAGE,
            "context_id": CONTEXT,
            "dispatch_a": DISPATCH_A,
            "dispatch_b": DISPATCH_B,
            "status_a": STATUS_A,
            "status_b": STATUS_B,
            "optional_submission": 0x3F,
            "optional_field_32": 2,
            "optional_field_46": 1,
            "optional_field_56": 1,
            "qctx_flags": 0x1000000000000000,
            "qctx_word_220": 0xFFFF080100000001,
            "qctx_word_338": 4,
        }
    if int(slot) == 1:
        return {
            "queue": QUEUE_1,
            "pointers": QUEUE_POINTERS_1,
            "item_ring": ITEM_RING_1,
            "job_list": JOB_LIST_1,
            "context_low": QUEUE_CONTEXT_LOW_1,
            "context_high": QUEUE_CONTEXT_HIGH_1,
            "channel_control": CHANNEL_RECORD_1,
            "grid": GRID + 1,
            "uuid": 0x159,
            "descriptor": DESCRIPTOR + DESCRIPTOR_STRIDE,
            "descriptor_low": DESCRIPTOR_LOW + DESCRIPTOR_STRIDE,
            "optional": OPTIONAL_1,
            "event": EVENT_1,
            "scheduler": SCHEDULER_1,
            "scheduler_slot": SCHEDULER_SLOT_1,
            "scheduler_work_id": 1,
            "shared_support": SHARED_SUPPORT_1,
            "support_state": SUPPORT_STATE_1,
            "zero_page": ZERO_PAGE_1,
            "context_id": CONTEXT + 1,
            "dispatch_a": 0xFFFFFC20001C8014,
            "dispatch_b": 0xFFFFFC20C07C0014,
            "status_a": STATUS_A + 0x10,
            "status_b": STATUS_B + 0x10,
            "optional_submission": 0x29,
            "optional_field_32": 3,
            "optional_field_46": 0,
            "optional_field_56": 2,
            "qctx_flags": 0x1000000000000000,
            "qctx_word_220": 0xFFFF080200000001,
            "qctx_word_338": 8,
        }
    if int(slot) == 2:
        return {
            "queue": QUEUE_2,
            "pointers": QUEUE_POINTERS_2,
            "item_ring": ITEM_RING_2,
            "job_list": JOB_LIST_1,
            "context_low": QUEUE_CONTEXT_LOW_2,
            "context_high": QUEUE_CONTEXT_HIGH_2,
            "channel_control": CHANNEL_RECORD_1,
            "grid": GRID + 3,
            "uuid": 0x183,
            "descriptor": DESCRIPTOR + 2 * DESCRIPTOR_STRIDE,
            "descriptor_low": DESCRIPTOR_LOW + 2 * DESCRIPTOR_STRIDE,
            "optional": OPTIONAL_2,
            "event": EVENT_2,
            "scheduler": SCHEDULER_2,
            "scheduler_slot": SCHEDULER_SLOT_2,
            "scheduler_work_id": 2,
            "shared_support": SHARED_SUPPORT_2,
            "support_state": SUPPORT_STATE_2,
            "zero_page": ZERO_PAGE_2,
            "context_id": CONTEXT + 1,
            "dispatch_a": 0xFFFFFC20001C801C,
            "dispatch_b": 0xFFFFFC20C07C001C,
            "status_a": STATUS_A + 0x10,
            "status_b": STATUS_B + 0x10,
            "optional_submission": 0x34,
            "optional_field_32": 3,
            "optional_field_46": 0,
            "optional_field_56": 3,
            "qctx_flags": 0x1000000000000000,
            "qctx_word_220": 0xFFFF080300000001,
            "qctx_word_338": 8,
        }
    if int(slot) == 3:
        return {
            "queue": QUEUE_3,
            "pointers": QUEUE_POINTERS_3,
            "item_ring": ITEM_RING_3,
            "job_list": JOB_LIST_1,
            "context_low": QUEUE_CONTEXT_LOW_3,
            "context_high": QUEUE_CONTEXT_HIGH_3,
            "channel_control": CHANNEL_RECORD_1,
            "grid": GRID + 3,
            "uuid": 0x183,
            "descriptor": DESCRIPTOR + 3 * DESCRIPTOR_STRIDE,
            "descriptor_low": DESCRIPTOR_LOW + 3 * DESCRIPTOR_STRIDE,
            "optional": OPTIONAL_3,
            "event": EVENT_3,
            "scheduler": SCHEDULER_3,
            "scheduler_slot": SCHEDULER_SLOT_3,
            "scheduler_work_id": 3,
            "shared_support": SHARED_SUPPORT_3,
            "support_state": SUPPORT_STATE_3,
            "zero_page": ZERO_PAGE_3,
            "context_id": CONTEXT + 1,
            "dispatch_a": 0xFFFFFC20001C801C,
            "dispatch_b": 0xFFFFFC20C07C001C,
            "status_a": STATUS_A + 0x10,
            "status_b": STATUS_B + 0x10,
            "optional_submission": 0x34,
            "optional_field_32": 3,
            "optional_field_46": 0,
            "optional_field_56": 3,
            "qctx_flags": 0x1000000000000000,
            "qctx_word_220": 0xFFFF080300000001,
            "qctx_word_338": 8,
            "metadata_ordinal": 2,
            "support_style": 2,
            "channel_control_style": 2,
            "fresh_lifetime": True,
        }
    raise ValueError("compute queue slot must be zero through three")


def _work_addresses(ordinal, fresh_command3_style=False):
    """Return queue-local and per-command objects for one measured dispatch."""
    ordinal = int(ordinal)
    spec = dict(_queue_addresses(
        _queue_slot(ordinal, fresh_command3_style=fresh_command3_style)))
    if ordinal == 3 and not fresh_command3_style:
        # The fourth native command returns to the context-3 pair's first
        # queue, but replaces all command-local metadata and the queue UUID.
        spec.update({
            "uuid": 0x17E,
            "descriptor": DESCRIPTOR + 3 * DESCRIPTOR_STRIDE,
            "descriptor_low": DESCRIPTOR_LOW + 3 * DESCRIPTOR_STRIDE,
            "optional": OPTIONAL_3,
            "event": EVENT_3,
            "scheduler": SCHEDULER_3,
            "scheduler_slot": SCHEDULER_SLOT_3,
            "scheduler_work_id": 3,
            "shared_support": SHARED_SUPPORT,
            "support_state": SUPPORT_STATE,
            "optional_submission": 0x2D,
            "optional_field_46": 1,
            "qctx_word_350": 0x000110038001A188,
            "qctx_word_358": 0x000020038001A1C1,
        })
    return spec


def _physical_read(backend, pa, size):
    backend.u.proxy.dc_ivac(pa, size)
    return bytes(backend.u.iface.readmem(pa, size))


def _build_channel_control(slot, ordinal=None):
    """Build the pair-local state from the output-positive source lifecycle."""
    if int(slot) not in (0, 1, 2):
        raise ValueError("compute channel-control slot must be zero, one, or two")
    out = bytearray(0x40)
    if ordinal is not None and int(ordinal) == 3:
        for offset, value in (
            (0x00, 0x00C8010402040202),
            (0x08, 0x000000002EE00000),
            (0x10, 0x0000000000100000),
            (0x20, 0x0002000000000000),
            (0x28, 0xBA00000000000000),
            (0x30, 0x0000000002000004),
        ):
            struct.pack_into("<Q", out, offset, value)
        return bytes(out)
    if int(slot) == 2:
        for offset, value in (
            (0x00, 0x00C8010402040302),
            (0x08, 0x0000000025800000),
            (0x10, 0x0000000000400000),
            (0x20, 0x0002000000000000),
            (0x28, 0x4C00000000000000),
            (0x30, 0x0000000003000003),
        ):
            struct.pack_into("<Q", out, offset, value)
        return bytes(out)
    if int(slot) == 1:
        for offset, value in (
            (0x00, 0x00C8010402040202),
            (0x08, 0x000000002EE00000),
            (0x10, 0x0000000000100000),
            (0x20, 0x0002000000000000),
            (0x28, 0xA000000000000000),
            (0x30, 0x0000000002000001),
        ):
            struct.pack_into("<Q", out, offset, value)
        return bytes(out)
    for offset, value in (
        (0x00, 0x000001000000FFFF),
        (0x20, 0x0002000000000000),
        (0x30, 0x00000000FF000000),
    ):
        struct.pack_into("<Q", out, offset, value)
    return bytes(out)


def _build_indirect_second_channel_control():
    """Build the pair-local control state at the native command-2 boundary."""
    out = bytearray(_build_channel_control(1))
    struct.pack_into("<Q", out, 0x28, 0x0700000000000000)
    struct.pack_into("<Q", out, 0x30, 0x0000000002000003)
    return bytes(out)


def _scheduler_for_ordinal(spec, ordinal):
    """Return a fresh scheduler record/state pair for one work ordinal."""
    ordinal = int(ordinal)
    if ordinal <= 3:
        return (
            spec["scheduler"],
            spec["scheduler_slot"],
            spec["scheduler_work_id"],
        )
    # The retained native history selects one of 36 physical records directly
    # from the monotonic submit sequence: sequence s uses slot (s + 1) mod 36.
    # Keep the first four independently measured records unchanged, then model
    # that physical reuse without resetting the work ID inside the record.
    pool_index = (ordinal + 1) % SCHEDULER_RING_RECORDS
    return (
        RUNTIME_SCHEDULER_POOL + pool_index * SCHEDULER_RECORD_STRIDE,
        RUNTIME_SCHEDULER_STATE + pool_index * 4,
        _work_ordinal(ordinal),
    )


def _refresh_runtime_slot(
        backend, spec, slot, ordinal,
        scheduler, scheduler_slot, scheduler_work_id,
        persistent_static=False):
    """Restore host-owned state before reusing one alternating compute slot."""
    slot = int(slot)
    backend._write_dva(
        scheduler,
        compute.build_compute_scheduler_record(
            scheduler_slot,
            work_id=scheduler_work_id,
        ),
    )
    backend._write_dva(scheduler_slot, struct.pack("<I", 1))
    support_style = int(spec.get("support_style", slot))
    if spec.get("native_indirect_second"):
        support = compute.build_compute_shared_support(
            OPERAND_TABLE,
            spec["support_state"],
            word_08=1,
            word_10=2,
            header=3,
            resource_class=0x15,
            cursor=0xA8,
            field_54=1,
            field_5c=1,
            final_kind=2,
            word_20=0x0000154800000048,
        )
    elif int(ordinal) == 3 and support_style != 2:
        support = compute.build_compute_shared_support(
            OPERAND_TABLE,
            spec["support_state"],
            word_08=1,
            word_10=2,
            header=3,
            resource_class=0x15,
            cursor=0x80,
            field_54=3,
            field_5c=1,
            final_kind=2,
            word_20=0x0000159000000090,
            word_28=0x0000150000000000,
        )
    elif support_style == 0:
        support = compute.build_compute_shared_support(
            OPERAND_TABLE,
            spec["support_state"],
            word_08=1,
            word_10=2,
            header=2,
            resource_class=0x15,
            cursor=0xA8,
            field_5c=1,
            final_kind=2,
        )
    elif support_style == 1:
        support = compute.build_compute_shared_support(
            OPERAND_TABLE,
            spec["support_state"],
            word_08=0,
            word_10=2,
            header=3,
            resource_class=0x15,
            cursor=0xA8,
            field_54=1,
            field_5c=1,
            final_kind=2,
        )
    elif support_style == 2:
        support = compute.build_compute_shared_support(
            OPERAND_TABLE,
            spec["support_state"],
            word_08=0,
            word_10=2,
            header=3,
            resource_class=0x15,
            cursor=0xA8,
            field_54=2,
            field_5c=1,
            final_kind=2,
            word_20=0x0000159000000090,
            word_28=0x0000150000000000,
        )
    else:
        raise ValueError("compute runtime slot is not measured")
    refreshed = [
        (scheduler, SCHEDULER_RECORD_STRIDE),
        (scheduler_slot, 4),
    ]
    # These objects are invariant over a persistent queue lifetime. Native
    # before/after captures show that firmware leaves shared_support unchanged;
    # zero_page is zero backing, while channel_control and job_list are fixed
    # for the queue. Initialize them for the first runtime item and retain them.
    if not persistent_static:
        backend._write_dva(spec["shared_support"], support)
        backend._write_dva(spec["zero_page"], bytes(PAGE))
        backend._write_dva(
            spec["channel_control"],
            (_build_indirect_second_channel_control()
             if spec.get("native_indirect_second") else
             _build_channel_control(
                 spec.get("channel_control_style", slot),
                 None if "channel_control_style" in spec else ordinal)),
        )
        backend._write_dva(
            spec["job_list"], g17p.build_job_list(spec["job_list"]))
        refreshed.extend((
            (spec["shared_support"], PAGE),
            (spec["zero_page"], PAGE),
            (spec["channel_control"], 0x40),
            (spec["job_list"], g17p.JOB_LIST_SIZE),
        ))
    backend._write_dva(
        spec["support_state"], struct.pack("<I", int(ordinal) + 1))
    for address in (spec["dispatch_a"], spec["dispatch_b"]):
        backend._write_dva(address, bytes(4))
    for address in (spec["status_a"], spec["status_b"]):
        backend._write_dva(address, bytes(8))
    refreshed.extend((
        (spec["support_state"], 4),
        (spec["dispatch_a"], 4),
        (spec["dispatch_b"], 4),
        (spec["status_a"], 8),
        (spec["status_b"], 8),
    ))
    return tuple(refreshed)


def _map_layout(space, layout):
    total = sum(size for _address, size, _name, _executable in layout)
    backing = space.u.memalign(PAGE, total)
    space.p.memset32(backing, 0, total)
    space.p.dc_civac(backing, total)
    mapped = {}
    offset = 0
    for address, size, name, executable in layout:
        pa = backing + offset
        flags = {
            "AttrIndex": MemoryAttr.Shared,
            "AP": 2,
            "nG": 1,
            "UXN": 0 if executable else 1,
            "OS": 1,
        }
        space.uat.iomap_at(space.context, address, pa, size, **flags)
        space.objects.append({
            "name": name,
            "va": address,
            "pa": pa,
            "size": size,
            "map_va": address,
            "map_pa": pa,
            "map_size": size,
            "flags": flags,
        })
        mapped[name] = (address, pa, size)
        offset += size
    return mapped


def _workload_vectors(index):
    base = 1000.0 + int(index) * 128.0
    values_a = [base + element for element in range(64)]
    values_b = [0.5 + float(index) for _element in range(64)]
    return values_a, values_b, [
        left + right for left, right in zip(values_a, values_b)
    ]


def prepare_client_workload(client, index, input_a_dependency=None):
    """Install distinct inputs/resource binding for one caller-owned dispatch."""
    outputs = client["outputs"]
    index = int(index)
    if index < 0:
        raise ValueError("compute workload index must be non-negative")
    command_slot = index % len(client["terminators"])
    values_a, values_b, _computed = _workload_vectors(index)
    if input_a_dependency is not None:
        values_a = list(input_a_dependency["expected"])
        input_a_dva = int(input_a_dependency["output_dva"])
        if len(values_a) != 64:
            raise ValueError("compute dependency must provide 64 input values")
    computed = [left + right for left, right in zip(values_a, values_b)]
    output = outputs[command_slot]
    active_elements = client.get(
        "dispatch_elements", [len(computed)] * len(outputs))[command_slot]
    if active_elements < 1 or active_elements > len(computed):
        raise ValueError(
            "compute dispatch writes %d elements, available output has %d" %
            (active_elements, len(computed)))
    expected = computed[:active_elements] + [0.0] * (
        len(computed) - active_elements)
    objects = client["objects"]
    space = client["space"]
    if command_slot < 2:
        input_a_name = "input_a"
        input_b_name = "input_b"
        default_input_a_dva = INPUT_A
        input_b_dva = INPUT_B
    else:
        input_a_name = "input_a_%02d" % command_slot
        input_b_name = "input_b_%02d" % command_slot
        default_input_a_dva = (
            INPUT_POOL_BASE
            + (command_slot - 2) * INPUT_POOL_WORKLOAD_STRIDE)
        input_b_dva = default_input_a_dva + PAGE
    if input_a_dependency is None:
        input_a_dva = default_input_a_dva
        space.write(objects[input_a_name][1], struct.pack("<64f", *values_a))
    space.write(objects[input_b_name][1], struct.pack("<64f", *values_b))
    resource_name = (
        "resource" if command_slot == 0 else
        "resource_%02d" % command_slot)
    if client.get("indirect_dispatch"):
        resource_dva = objects[resource_name][0]
        argument_name = "indirect_arguments_%02d" % command_slot
        binding_name = "indirect_helper_binding_%02d" % command_slot
        argument_dva = objects[argument_name][0]
        binding_dva = (
            objects[binding_name][0]
            + client.get("helper_binding_offset", 0))
        grid = client["dispatch_grids"][command_slot]
        threadgroup = client["threadgroups"][command_slot]
        if any(grid[axis] % threadgroup[axis] for axis in range(3)):
            raise ValueError(
                "indirect test grid must be divisible by its threadgroup")
        threadgroups = tuple(
            grid[axis] // threadgroup[axis] for axis in range(3))
        space.write(
            objects[argument_name][1], struct.pack("<3I", *threadgroups))
        space.write(
            objects[binding_name][1],
            bytes(client.get("helper_binding_offset", 0))
            + compute.build_indirect_helper_binding(
                argument_dva,
                resource_dva + compute.INDIRECT_GEOMETRY_OFFSET,
                size=(objects[binding_name][2]
                      - client.get("helper_binding_offset", 0))),
        )
        space.write(
            objects[resource_name][1],
            compute.build_indirect_resource_table(
                (client["helper_constant_dva"], binding_dva),
                (input_a_dva, input_b_dva, output["dva"]),
                size=RESOURCE_SIZE,
            ),
        )
    else:
        space.write(
            objects[resource_name][1],
            compute.build_buffer_resource_table(
                (input_a_dva, input_b_dva, output["dva"]),
                size=RESOURCE_SIZE),
        )
    # The shader writes exactly 64 floats. Clearing the observed result extent
    # is sufficient when a command slot is reused and avoids transferring an
    # unrelated 16 KiB tail over the debug proxy on every submission.
    space.write(output["pa"], bytes(64 * 4))
    return {
        "index": index,
        "output_dva": output["dva"],
        "output_pa": output["pa"],
        "expected": expected,
        "input_a_dependency": input_a_dependency,
        "slot": command_slot,
        "terminator": client["terminators"][command_slot],
    }


def build_client_graph(backend, distinct_empty_high=False,
                       native_shader_attributes=False, workload_count=1,
                       client_slot_count=None, dispatch_grids=None,
                       threadgroups=None, indirect_dispatch=False,
                       indirect_layout="native"):
    """Build context 2, all registration storage, and caller add3 objects."""
    if indirect_dispatch:
        if indirect_layout not in (
                "native", "native_program", "native_helper_graph",
                "native_argument", "native_helpers",
                "native_helper_constant", "native_helper_binding",
                "helper_binding_offset", "native_helper_binding_page",
                "native_binding_public_program",
                "relative", "public", "relocated"):
            raise ValueError("unknown indirect client layout %r" % indirect_layout)
        if indirect_layout in ("public", "native_binding_public_program"):
            resource_base = INDIRECT_PUBLIC_RESOURCE
            cdm_base = INDIRECT_PUBLIC_CDM
            shader_base = INDIRECT_PUBLIC_SHADER
        else:
            native_program = indirect_layout in (
                "native", "native_program", "native_helper_graph")
            resource_base = (
                INDIRECT_NATIVE_RESOURCE if native_program else RESOURCE)
            cdm_base = INDIRECT_NATIVE_CDM if native_program else CDM
            shader_base = INDIRECT_NATIVE_SHADER if native_program else SHADER
        native_argument = indirect_layout in (
            "native", "native_helper_graph", "native_argument")
        native_helper_constant = indirect_layout in (
            "native", "native_helper_graph", "native_helpers",
            "native_helper_constant")
        native_helper_binding = indirect_layout in (
            "native", "native_helper_graph", "native_helpers",
            "native_helper_binding", "native_binding_public_program")
        if indirect_layout == "native":
            output_base = INDIRECT_NATIVE_OUTPUT
        elif native_argument:
            # The captured argument address collides with the old relocated
            # output address. Keep the split's output disjoint.
            output_base = OUTPUT_POOL_BASE
        else:
            output_base = OUTPUT
        if native_argument:
            argument_base = INDIRECT_NATIVE_ARGUMENT_BASE
        else:
            argument_base = INDIRECT_ARGUMENT_BASE
        if native_helper_constant:
            helper_constant_page = INDIRECT_NATIVE_HELPER_CONSTANT_PAGE
            helper_constant_offset = INDIRECT_NATIVE_HELPER_CONSTANT_OFFSET
        else:
            helper_constant_page = INDIRECT_HELPER_CONSTANT
            helper_constant_offset = 0
        if native_helper_binding:
            helper_binding_base = INDIRECT_NATIVE_HELPER_BINDING_BASE
            helper_binding_offset = INDIRECT_NATIVE_HELPER_BINDING_OFFSET
        elif indirect_layout == "helper_binding_offset":
            helper_binding_base = INDIRECT_HELPER_BINDING_BASE
            helper_binding_offset = INDIRECT_NATIVE_HELPER_BINDING_OFFSET
        elif indirect_layout == "native_helper_binding_page":
            helper_binding_base = INDIRECT_NATIVE_HELPER_BINDING_BASE
            helper_binding_offset = 0
        elif indirect_layout == "relative":
            # Independently captured A18 layouts move this page, the shader,
            # CDM, and resource allocation as one group. The helper control
            # page is one 0x10000 allocation quantum below the shader and its
            # live body begins at +0xb0.
            helper_binding_base = shader_base - 0x10000
            helper_binding_offset = INDIRECT_NATIVE_HELPER_BINDING_OFFSET
        elif indirect_layout == "public":
            helper_binding_base = INDIRECT_PUBLIC_BINDING_BASE
            helper_binding_offset = INDIRECT_NATIVE_HELPER_BINDING_OFFSET
        else:
            helper_binding_base = INDIRECT_HELPER_BINDING_BASE
            helper_binding_offset = 0
    else:
        resource_base = RESOURCE
        cdm_base = CDM
        shader_base = SHADER
        output_base = OUTPUT
        argument_base = INDIRECT_ARGUMENT_BASE
        helper_constant_page = INDIRECT_HELPER_CONSTANT
        helper_constant_offset = 0
        helper_binding_base = INDIRECT_HELPER_BINDING_BASE
        helper_binding_offset = 0
    helper_constant_dva = helper_constant_page + helper_constant_offset

    space = type(backend.space)(backend.u, CONTEXT, shader_base)
    space.use_absent_handoff()
    root = space.uat.ttbr0_base
    backend.u.proxy.memset32(root, 0, PAGE)
    backend.u.proxy.dc_civac(root, PAGE)
    if distinct_empty_high:
        high_root = backend.u.memalign(PAGE, PAGE)
        backend.u.proxy.memset32(high_root, 0, PAGE)
        backend.u.proxy.dc_civac(high_root, PAGE)
        space.uat.ttbr1_base = high_root
    else:
        space.uat.ttbr1_base = backend.firmware_high_root
    space.uat.initialized = True
    # iomap_at() walks from the hardware context table.  Install this space's
    # root before the first mapping so it cannot construct an implicit root and
    # then lose that tree when context 2 is bound below.
    space.uat.set_l0(CONTEXT, 0, root, CONTEXT)
    space.uat.set_l0(CONTEXT, 1, space.uat.ttbr1_base, CONTEXT)
    workload_count = int(workload_count)
    if client_slot_count is None:
        client_slot_count = workload_count
    client_slot_count = int(client_slot_count)
    if workload_count < 1:
        raise ValueError("compute client needs at least one workload")
    if not 1 <= client_slot_count <= workload_count:
        raise ValueError(
            "compute client slot count must be within the workload count")
    if workload_count > 1:
        # The measured second native compute command is a context-3 command.
        # Alias the caller-owned graph into that slot so its descriptor can be
        # reproduced exactly without copying another address space.
        space.uat.set_l0(CONTEXT + 1, 0, root, CONTEXT + 1)
        space.uat.set_l0(
            CONTEXT + 1, 1, space.uat.ttbr1_base, CONTEXT + 1)
    space.uat.flush_dirty()
    space.uat.invalidate_cache()

    layout = [
        (OPERAND_PAGE_LIST_BASE, OPERAND_PAGE_LIST_SIZE,
         "operand_page_lists", False),
        (OPERAND_TABLE, OPERAND_TABLE_SIZE, "operand_table", False),
        (STATE_BASE, STATE_SIZE, "state_scratch", False),
        (NATIVE_CONTROL_TABLE_A, PAGE, "native_control_table_a", False),
    ]
    operand_slots = min(2, client_slot_count)
    command_slots = client_slot_count
    dispatch_grids = list(dispatch_grids or ((64, 1, 1),) * command_slots)
    threadgroups = list(threadgroups or ((32, 1, 1),) * command_slots)
    if len(dispatch_grids) != command_slots or len(threadgroups) != command_slots:
        raise ValueError(
            "dispatch geometry must provide one grid and threadgroup per command slot")
    dispatch_grids = [tuple(int(value) for value in grid)
                      for grid in dispatch_grids]
    threadgroups = [tuple(int(value) for value in group)
                    for group in threadgroups]
    for slot in range(operand_slots):
        for index in range(compute.COMPUTE_OPERAND_TABLE_ENTRIES):
            layout.append((
                OPERAND_BUFFER_BASE
                + slot * OPERAND_BUFFER_WORKLOAD_STRIDE
                + index * compute.COMPUTE_OPERAND_BUFFER_STRIDE,
                compute.COMPUTE_OPERAND_BUFFER_SIZE,
                ("operand_tranche_%02d" % index if slot == 0 else
                 "operand_tranche_01_%02d" % index),
                False,
            ))
    layout.extend((
        (CODE_IMAGE, PAGE, "code_image", True),
        (resource_base, RESOURCE_SIZE, "resource", False),
        (cdm_base, CDM_SIZE, "cdm", True),
        # G17P's native compute leaves carry UXN=1 here.  Under this UAT
        # permission encoding that is the GPU-readable/writable class; it is
        # independent of the firmware-side executable interpretation.
        (shader_base, SHADER_SIZE, "shader", not native_shader_attributes),
        (INPUT_A, PAGE, "input_a", False),
        (INPUT_B, PAGE, "input_b", False),
        (output_base, PAGE, "output", False),
        (ROBUSTNESS, PAGE, "robustness", False),
    ))
    for slot in range(1, command_slots):
        layout.extend((
            (resource_base + slot * CLIENT_WORKLOAD_STRIDE, RESOURCE_SIZE,
             "resource_%02d" % slot, False),
            (cdm_base + slot * CLIENT_WORKLOAD_STRIDE, CDM_SIZE,
             "cdm_%02d" % slot, True),
            (shader_base + slot * CLIENT_WORKLOAD_STRIDE, SHADER_SIZE,
             "shader_%02d" % slot, not native_shader_attributes),
        ))
    if operand_slots > 1:
        layout.append((
            ROBUSTNESS + ROBUSTNESS_WORKLOAD_STRIDE, PAGE,
            "robustness_01", False))
    for index in range(1, command_slots):
        if index >= 2:
            input_a = INPUT_POOL_BASE + (index - 2) * INPUT_POOL_WORKLOAD_STRIDE
            layout.extend((
                (input_a, PAGE, "input_a_%02d" % index, False),
                (input_a + PAGE, PAGE, "input_b_%02d" % index, False),
            ))
        output_dva = (
            output_base + OUTPUT_WORKLOAD_STRIDE if index == 1 else
            OUTPUT_POOL_BASE + (index - 2) * PAGE)
        layout.append((
            output_dva, PAGE, "output_%02d" % index, False))
    if indirect_dispatch:
        layout.append((
            helper_constant_page, PAGE,
            "indirect_helper_constant", False))
        for slot in range(command_slots):
            argument_dva = (
                argument_base + slot * INDIRECT_ARGUMENT_STRIDE)
            layout.extend((
                (argument_dva, PAGE,
                 "indirect_arguments_%02d" % slot, False),
                (helper_binding_base + slot * PAGE, PAGE,
                 "indirect_helper_binding_%02d" % slot, True),
            ))
    output_ranges = [
        (address, address + size, name)
        for address, size, name, _executable in layout
        if name == "output" or name.startswith("output_")
    ]
    input_ranges = [
        (address, address + size, name)
        for address, size, name, _executable in layout
        if (name in ("resource", "cdm", "shader", "input_a", "input_b")
            or name.startswith((
                "resource_", "cdm_", "shader_", "input_a_", "input_b_")))
    ]
    for output_start, output_end, output_name in output_ranges:
        for input_start, input_end, input_name in input_ranges:
            if output_start < input_end and input_start < output_end:
                raise ValueError(
                    "caller output %s [%#x,%#x) overlaps %s [%#x,%#x)" %
                    (output_name, output_start, output_end,
                     input_name, input_start, input_end))
    objects = _map_layout(space, layout)

    def write(name, body):
        _address, pa, size = objects[name]
        if len(body) > size:
            raise ValueError("%s body is too large" % name)
        space.write(pa, body)

    write(
        "operand_page_lists",
        compute.build_compute_operand_page_lists(
            OPERAND_BUFFER_BASE,
            entries=compute.COMPUTE_OPERAND_TABLE_ENTRIES,
        ),
    )
    write(
        "operand_table",
        compute.build_compute_operand_table(
            OPERAND_BUFFER_BASE,
            entries=compute.COMPUTE_OPERAND_TABLE_ENTRIES,
        ),
    )
    write(
        "code_image",
        build_add3_code_image(),
    )
    if indirect_dispatch:
        write(
            "indirect_helper_constant",
            bytes(helper_constant_offset)
            + compute.build_indirect_helper_constant(
                size=PAGE - helper_constant_offset),
        )

    def shader_body(shader_dva):
        if not indirect_dispatch:
            return build_add3_preamble(shader_dva)
        body = bytearray(0x100 + len(build_add3_preamble(
            shader_dva + 0x100)))
        main = build_indirect_add3_preamble(shader_dva)
        helper = build_add3_preamble(shader_dva + 0x100)
        body[:len(main)] = main
        body[0x100:0x100 + len(helper)] = helper
        return bytes(body)

    def cdm_stream(shader_dva, resource_dva, grid, threadgroup):
        if not indirect_dispatch:
            return compute.build_cdm_stream((
                compute.build_direct_dispatch(
                    shader_dva,
                    grid=grid,
                    threadgroup=threadgroup,
                    config=0x80000,
                    constant=0x1000000,
                    tail=0x60000160,
                ),
            ))
        # The inline grid is ignored in indirect mode.  Match the native
        # pre-helper image while the generated six-word block carries the
        # actual global and local dimensions.
        main = compute.build_direct_dispatch(
            shader_dva,
            grid=(96, 1, 1),
            threadgroup=threadgroup,
            config=0x880000,
            constant=0x1000000,
            tail=0x60000160,
        )
        helper = compute.build_indirect_grid_setup(
            shader_dva + 0x100,
            resource_dva + compute.INDIRECT_GEOMETRY_OFFSET,
            constant=0x01000000,
        )
        return compute.build_indirect_cdm_stream(main, helper)

    write("shader", shader_body(shader_base))
    stream = cdm_stream(
        shader_base, resource_base, dispatch_grids[0], threadgroups[0])
    write("cdm", stream)
    for slot in range(1, command_slots):
        shader_dva = shader_base + slot * CLIENT_WORKLOAD_STRIDE
        resource_dva = resource_base + slot * CLIENT_WORKLOAD_STRIDE
        write(
            "shader_%02d" % slot,
            shader_body(shader_dva),
        )
        write(
            "cdm_%02d" % slot,
            cdm_stream(
                shader_dva, resource_dva,
                dispatch_grids[slot], threadgroups[slot]),
        )

    outputs = [{
        "dva": output_base,
        "pa": objects["output"][1],
        "name": "output",
    }]
    outputs.extend({
        "dva": (output_base + OUTPUT_WORKLOAD_STRIDE if index == 1 else
                OUTPUT_POOL_BASE + (index - 2) * PAGE),
        "pa": objects["output_%02d" % index][1],
        "name": "output_%02d" % index,
    } for index in range(1, command_slots))
    client = {
        "space": space,
        "objects": objects,
        "outputs": outputs,
        "terminator": cdm_base + len(stream) - 4,
        "terminators": [
            cdm_base + slot * CLIENT_WORKLOAD_STRIDE + len(stream) - 4
            for slot in range(command_slots)
        ],
        "dispatch_elements": [
            grid[0] * grid[1] * grid[2] for grid in dispatch_grids
        ],
        "dispatch_grids": dispatch_grids,
        "threadgroups": threadgroups,
        "indirect_dispatch": bool(indirect_dispatch),
        "indirect_layout": indirect_layout,
        "resource_base": resource_base,
        "cdm_base": cdm_base,
        "shader_base": shader_base,
        "helper_constant_dva": helper_constant_dva,
        "helper_binding_offset": helper_binding_offset,
    }
    initial = prepare_client_workload(client, 0)

    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", CONTEXT << 48)
    backend.u.inst("dsb sy")

    output_pa = initial["output_pa"]
    if any(_physical_read(backend, output_pa, PAGE)):
        raise RuntimeError("generated add3 output did not start zero")
    print(
        "COMPUTE built context %d roots low=%#x high=%#x%s: "
        "%d operand tranches in %d command namespace(s), "
        "field-built CDM/preamble/resources plus caller code image, "
        "native_shader_attributes=%d, "
        "output %#x -> PA %#x" %
        (CONTEXT, root, space.uat.ttbr1_base,
         " (distinct empty high)" if distinct_empty_high else "",
         compute.COMPUTE_OPERAND_TABLE_ENTRIES * operand_slots,
         command_slots,
         native_shader_attributes, outputs[0]["dva"], output_pa),
        flush=True,
    )
    client.update({
        "output_pa": output_pa,
        "expected": initial["expected"],
    })
    return client


def _ensure_firmware(backend, address, size):
    backend._ensure_firmware_range(address, size)


def _alias_context0(backend, high, low, size):
    _ensure_firmware(backend, high, size)
    high_page = high & ~(PAGE - 1)
    low_page = low & ~(PAGE - 1)
    end = (high + size + PAGE - 1) & ~(PAGE - 1)
    for page in range(high_page, end, PAGE):
        ranges = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, page, PAGE)
        if not ranges or ranges[0][0] is None:
            raise RuntimeError("firmware alias source %#x is unmapped" % page)
        backend.space.uat.iomap_at(
            0, low_page + page - high_page, ranges[0][0], PAGE,
            AttrIndex=MemoryAttr.Shared, AP=2, nG=1, UXN=0, OS=1,
        )


def _apply_status_addresses(spec, ordinal, status_addresses):
    """Replace one command's default completion destinations when requested."""
    if status_addresses is None:
        return
    try:
        status_a, status_b = status_addresses[int(ordinal)]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(
            "missing status destinations for compute workload %d" % ordinal
        ) from exc
    status_a = int(status_a)
    status_b = int(status_b)
    if not status_a or not status_b or (status_a | status_b) & 3:
        raise ValueError(
            "compute status destinations must be nonzero and word aligned")
    spec["status_a"] = status_a
    spec["status_b"] = status_b


def _apply_user_timestamp_addresses(spec, ordinal, timestamp_addresses):
    """Set one command's caller-visible timestamp destinations."""
    if timestamp_addresses is None:
        return
    try:
        start, end = timestamp_addresses[int(ordinal)]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(
            "missing user timestamp destinations for compute workload %d" %
            ordinal
        ) from exc
    start = int(start)
    end = int(end)
    if (start | end) & 7:
        raise ValueError(
            "compute user timestamp destinations must be qword aligned")
    spec["user_timestamp_start"] = start
    spec["user_timestamp_end"] = end


def build_firmware_graph(backend, terminator, client_space,
                         alias_context0_queue=False, item_capacity=1,
                         fresh_command3_style=False,
                         indirect_dispatch=False, resource_base=RESOURCE,
                         cdm_base=CDM, status_addresses=None,
                         user_timestamp_addresses=None,
                         initial_registers=None, sampler_array=0,
                         sampler_count=0):
    """Build every direct CL2 object at the hardware-tested placement."""
    if item_capacity < 1:
        raise ValueError("compute queue needs at least one item slot")
    graph_slot_count = min(
        4 if fresh_command3_style else 3, int(item_capacity))
    work_slot_count = min(4, int(item_capacity))
    descriptor_count = int(item_capacity)
    descriptor_extent = ((descriptor_count - 1) * DESCRIPTOR_STRIDE
                         + DESCRIPTOR_BODY_SIZE)
    optional_extent = ((graph_slot_count - 1) * OPTIONAL_STRIDE
                       + compute.COMPUTE_OPTIONAL_SIZE)
    event_extent = ((graph_slot_count - 1) * EVENT_STRIDE
                    + compute.COMPUTE_EVENT_SIZE)
    scheduler_extent = PAGE
    runtime_scheduler_count = max(0, int(item_capacity) - 2)
    queue_count = graph_slot_count
    queue_layout = [_queue_addresses(slot) for slot in range(queue_count)]
    work_layout = [_work_addresses(ordinal)
                   for ordinal in range(work_slot_count)]
    if indirect_dispatch:
        # Keep both commands on the allocation pair observed in the native
        # two-command lifecycle. Firmware then creates command 2's retained
        # predecessor state instead of the host manufacturing it later.
        queue_layout[0] = _indirect_first_addresses()
        work_layout[0].update(queue_layout[0])
        if len(queue_layout) > 1:
            # The second native indirect publication switches to queue-grid
            # slot 4.  That queue retains command 1 as consumed history and
            # appends command 2 at item-ring head 6.
            queue_layout[1]["grid"] = 4
            queue_layout[1]["uuid"] = 0x14D
    for ordinal, spec in enumerate(queue_layout):
        _apply_status_addresses(spec, ordinal, status_addresses)
        _apply_user_timestamp_addresses(
            spec, ordinal, user_timestamp_addresses)
    for address, size in (
        (SCHEDULER_PAGE, scheduler_extent),
        (SHARED_STATE, PAGE),
        (SHARED_SUPPORT, PAGE),
        (SUPPORT_STATE, PAGE),
        (JOB_LIST_BASE, 0x60),
        (CHANNEL_RECORD, 0x40),
        (OPTIONAL, optional_extent),
        (EVENT, event_extent),
        (RUNTIME_EVENT_BASE,
         int(item_capacity) * compute.COMPUTE_EVENT_SIZE),
    ):
        _ensure_firmware(backend, address, size)
    if runtime_scheduler_count:
        runtime_scheduler_extent = (
            runtime_scheduler_count * SCHEDULER_RECORD_STRIDE)
        runtime_state_extent = runtime_scheduler_count * 4
        _ensure_firmware(
            backend, RUNTIME_SCHEDULER_POOL, runtime_scheduler_extent)
        _ensure_firmware(
            backend, RUNTIME_SCHEDULER_STATE, runtime_state_extent)
        backend._write_dva(
            RUNTIME_SCHEDULER_POOL, bytes(runtime_scheduler_extent))
        backend._write_dva(
            RUNTIME_SCHEDULER_STATE, bytes(runtime_state_extent))
    if status_addresses is not None:
        for ordinal in range(int(item_capacity)):
            status_spec = {}
            _apply_status_addresses(
                status_spec, ordinal, status_addresses)
            for address in (
                    status_spec["status_a"], status_spec["status_b"]):
                _ensure_firmware(backend, address, 8)
    for index in range(graph_slot_count):
        _ensure_firmware(
            backend,
            ZERO_PAGE + (index & 1) * ROBUSTNESS_WORKLOAD_STRIDE,
            PAGE,
        )
        for address in (
                DISPATCH_A + index * 4,
                DISPATCH_B + index * 4,
                STATUS_A + index * 0x10,
                STATUS_B + index * 0x10):
            _ensure_firmware(backend, address, 8)
    for spec in queue_layout:
        for address, size in (
            (spec["pointers"], 0x80),
            (spec["item_ring"], QUEUE_PAIR_OBJECT_STRIDE),
            (spec["queue"], g17p.QUEUE_RECORD_STRIDE),
            (spec["context_high"], compute.COMPUTE_QUEUE_CONTEXT_EXTENT),
            (spec["optional"], compute.COMPUTE_OPTIONAL_SIZE),
            (spec["event"], compute.COMPUTE_EVENT_SIZE),
            (spec["scheduler"], SCHEDULER_RECORD_STRIDE),
            (spec["scheduler_slot"], 4),
            (spec["shared_support"], PAGE),
            (spec["support_state"], PAGE),
            (spec["zero_page"], PAGE),
        ):
            _ensure_firmware(backend, address, size)
    if indirect_dispatch:
        for ordinal in range(1, int(item_capacity)):
            runtime = _indirect_runtime_addresses(ordinal)
            for address, size in (
                    (runtime["pointers"], 0x80),
                    (runtime["item_ring"], QUEUE_PAIR_OBJECT_STRIDE),
                    (runtime["optional"], compute.COMPUTE_OPTIONAL_SIZE),
                    (runtime["event"], compute.COMPUTE_EVENT_SIZE),
                    (runtime["scheduler"], SCHEDULER_RECORD_STRIDE),
                    (runtime["scheduler_slot"], 4),
                    (runtime["zero_page"], PAGE),
                    (runtime["dispatch_a"], 8),
                    (runtime["dispatch_b"], 8),
                    (runtime["status_a"], 8),
                    (runtime["status_b"], 8)):
                _ensure_firmware(backend, address, size)
    for spec in work_layout:
        for address, size in (
            (spec["optional"], compute.COMPUTE_OPTIONAL_SIZE),
            (spec["event"], compute.COMPUTE_EVENT_SIZE),
            (spec["scheduler"], SCHEDULER_RECORD_STRIDE),
            (spec["scheduler_slot"], 4),
            (spec["shared_support"], PAGE),
            (spec["support_state"], PAGE),
            (spec["zero_page"], PAGE),
        ):
            _ensure_firmware(backend, address, size)
    _alias_context0(
        backend, DESCRIPTOR, DESCRIPTOR_LOW, descriptor_extent)
    if alias_context0_queue:
        for spec in queue_layout:
            _alias_context0(
                backend, spec["context_high"], spec["context_low"],
                compute.COMPUTE_QUEUE_CONTEXT_EXTENT)

    # Retain the adjacent intrusive list heads, but keep the source lifecycle's
    # already output-positive queue head for both queues in the pair.
    for offset in (0, 0x18, 0x30, 0x48):
        address = JOB_LIST_BASE + offset
        backend._write_dva(address, g17p.build_job_list(address))

    initialized_channel_controls = set()
    for slot, spec in enumerate(queue_layout):
        if spec["channel_control"] in initialized_channel_controls:
            continue
        backend._write_dva(
            spec["channel_control"], _build_channel_control(slot))
        initialized_channel_controls.add(spec["channel_control"])

    scheduler_page = bytearray(PAGE)
    for index in range(36):
        struct.pack_into(
            "<Q", scheduler_page, index * 0x100,
            SHARED_STATE + index * 4)
    for index in range(graph_slot_count):
        offset = 0x100 + index * SCHEDULER_RECORD_STRIDE
        scheduler_page[offset:offset + 0x100] = (
            compute.build_compute_scheduler_record(
                SCHEDULER_SLOT + index * 4))
    backend._write_dva(SCHEDULER_PAGE, scheduler_page)
    scheduler_state = bytearray(PAGE)
    for index in range(graph_slot_count):
        struct.pack_into("<I", scheduler_state, 4 + index * 4, 1)
    backend._write_dva(SHARED_STATE, scheduler_state)

    backend._write_dva(
        SHARED_SUPPORT,
        compute.build_compute_shared_support(
            OPERAND_TABLE, SUPPORT_STATE,
            word_08=1, word_10=2, header=2,
            resource_class=0x15, cursor=0xA8,
            field_5c=1, final_kind=2,
        ),
    )
    backend._write_dva(
        SUPPORT_STATE, compute.build_compute_shared_state(1))
    if queue_count > 1:
        second = queue_layout[1]
        backend._write_dva(
            second["scheduler"],
            compute.build_compute_scheduler_record(
                second["scheduler_slot"],
                work_id=second["scheduler_work_id"],
            ),
        )
        backend._write_dva(second["scheduler_slot"], struct.pack("<I", 1))
        backend._write_dva(
            second["shared_support"],
            compute.build_compute_shared_support(
                OPERAND_TABLE,
                second["support_state"],
                word_08=0,
                word_10=2,
                header=3,
                resource_class=0x15,
                cursor=0xA8,
                field_54=1,
                field_5c=1,
                final_kind=2,
            ),
        )
        backend._write_dva(
            second["support_state"],
            compute.build_compute_shared_state(2),
        )
    initial = queue_layout[0]
    if initial.get("native_indirect_first"):
        backend._write_dva(
            initial["scheduler"],
            compute.build_compute_scheduler_record(
                initial["scheduler_slot"],
                work_id=initial["scheduler_work_id"],
            ),
        )
        backend._write_dva(
            initial["scheduler_slot"], struct.pack("<I", 1))
        backend._write_dva(
            initial["shared_support"],
            compute.build_compute_shared_support(
                OPERAND_TABLE,
                initial["support_state"],
                word_08=1,
                word_10=2,
                header=3,
                resource_class=0x15,
                cursor=0xA8,
                field_54=1,
                field_5c=1,
                final_kind=2,
                word_20=0x0000154800000048,
            ),
        )
        backend._write_dva(
            initial["support_state"],
            compute.build_compute_shared_state(1),
        )
        backend._write_dva(
            initial["channel_control"],
            _build_indirect_second_channel_control(),
        )
    if queue_count > 2:
        third = queue_layout[2]
        backend._write_dva(
            third["scheduler"],
            compute.build_compute_scheduler_record(
                third["scheduler_slot"],
                work_id=third["scheduler_work_id"],
            ),
        )
        backend._write_dva(third["scheduler_slot"], struct.pack("<I", 1))
        backend._write_dva(
            third["shared_support"],
            compute.build_compute_shared_support(
                OPERAND_TABLE,
                third["support_state"],
                word_08=0,
                word_10=2,
                header=3,
                resource_class=0x15,
                cursor=0xA8,
                field_54=2,
                field_5c=1,
                final_kind=2,
                word_20=0x0000159000000090,
                word_28=0x0000150000000000,
            ),
        )
        backend._write_dva(
            third["support_state"],
            compute.build_compute_shared_state(3),
        )
    for spec in queue_layout:
        backend._write_dva(
            spec["zero_page"], bytes(PAGE))
    for index in range(graph_slot_count):
        for address in (
                DISPATCH_A + index * 4,
                DISPATCH_B + index * 4,
                STATUS_A + index * 0x10,
                STATUS_B + index * 0x10):
            backend._write_dva(address, bytes(8))

    queues = []
    for slot, spec in enumerate(queue_layout):
        pointers = bytearray(0x80)
        pointers[:g17p.QUEUE_PTR_BLOCK_SIZE] = g17p.build_queue_pointers()
        struct.pack_into("<I", pointers, 0x60, 0x500)
        seed_indirect_history = bool(indirect_dispatch and slot == 1)
        if seed_indirect_history:
            for offset in (
                    g17p.QUEUE_PTR_DONE,
                    g17p.QUEUE_PTR_READ,
                    g17p.QUEUE_PTR_WRITE):
                struct.pack_into("<I", pointers, offset, 3)
        backend._write_dva(spec["pointers"], pointers)
        item_ring = bytearray(QUEUE_PAIR_OBJECT_STRIDE)
        if seed_indirect_history:
            struct.pack_into(
                "<3Q", item_ring, 0, DESCRIPTOR, OPTIONAL, EVENT)
        backend._write_dva(spec["item_ring"], item_ring)
        queue_record = bytearray(g17p.build_queue_record(
            spec["pointers"], spec["item_ring"], spec["job_list"],
            spec["channel_control"], uuid=spec["uuid"], priority=2,
            prio5=2, unk_2c=2, unk_38=0, unk_94=0,
            sentinel_size=2,
        ))
        if seed_indirect_history:
            struct.pack_into("<I", queue_record, g17p.QUEUE_GPU_RPTR2, 3)
        backend._write_dva(
            spec["queue"],
            queue_record,
        )
        backend._write_dva(
            spec["context_high"],
            compute.build_compute_queue_context(
                spec["descriptor"], spec["queue"], spec["grid"],
                flags_200=spec["qctx_flags"],
                word_220=spec["qctx_word_220"],
                word_330=0,
                word_338=spec["qctx_word_338"],
                word_350=(0x000110038001A002
                          + slot * (DESCRIPTOR_STRIDE // 0x20)),
                word_358=(0x000020038001A03B
                          + slot * (DESCRIPTOR_STRIDE // 0x20)),
                word_378=0x003FFFFFFFFFFFFF,
            ),
        )
        queues.append(G17PQueue(
            backend._read_dva, spec["queue"], spec["grid"]))
    initial = queue_layout[0]
    backend._write_dva(
        initial["optional"],
        compute.build_compute_optional(
            initial["context_low"], initial["context_high"],
            grid_index=initial["grid"],
            submission_ordinal=initial["optional_submission"],
            shared_control=initial["shared_support"],
            channel_control=initial["channel_control"],
            uuid=initial["uuid"],
            field_46=initial["optional_field_46"],
            field_1e=2,
            field_32=initial["optional_field_32"],
            field_56=initial["optional_field_56"],
            field_5e=2,
        ),
    )
    backend._write_dva(
        initial["event"], bytes(compute.COMPUTE_EVENT_SIZE))
    backend._write_dva(
        initial["descriptor"],
        compute.build_compute_descriptor(
            (_registers_for_workload(
                0, indirect_dispatch=indirect_dispatch,
                resource_base=resource_base, cdm_base=cdm_base)
             if initial_registers is None else initial_registers),
            scheduler_record=initial["scheduler"],
            low_alias=initial["descriptor_low"],
            cdm_terminator=terminator,
            submit_sequence=0,
            context_id=initial["context_id"],
            grid_index=initial["grid"],
            dispatch_a=initial["dispatch_a"],
            dispatch_b=initial["dispatch_b"],
            status_a=initial["status_a"],
            status_b=initial["status_b"],
            user_timestamp_start=initial.get("user_timestamp_start", 0),
            user_timestamp_end=initial.get("user_timestamp_end", 0),
            zero_page=initial["zero_page"],
            shared_control=initial["shared_support"],
            protection_index=1,
            support_control=0xE0A00001,
            support_flags=0,
            sampler_array=sampler_array,
            sampler_count=sampler_count,
        ),
    )

    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    backend.space.flush()
    for address, size in (
        (initial["descriptor"], compute.COMPUTE_DESCRIPTOR_SIZE),
        (initial["optional"], compute.COMPUTE_OPTIONAL_SIZE),
        (initial["event"], compute.COMPUTE_EVENT_SIZE),
        (SCHEDULER_PAGE, scheduler_extent), (SHARED_STATE, PAGE),
        (initial["shared_support"], PAGE),
        (initial["support_state"], PAGE),
        (JOB_LIST_BASE, 0x60),
        (initial["channel_control"], 0x40),
    ):
        backend._clean_dva_range(address, size)
    for spec in queue_layout:
        for address, size in (
            (spec["pointers"], 0x80),
            (spec["item_ring"], QUEUE_PAIR_OBJECT_STRIDE),
            (spec["queue"], g17p.QUEUE_RECORD_STRIDE),
            (spec["context_high"], compute.COMPUTE_QUEUE_CONTEXT_SIZE),
        ):
            backend._clean_dva_range(address, size)
    for spec in queue_layout:
        for address, size in (
            (spec["optional"], compute.COMPUTE_OPTIONAL_SIZE),
            (spec["event"], compute.COMPUTE_EVENT_SIZE),
            (spec["scheduler"], SCHEDULER_RECORD_STRIDE),
            (spec["scheduler_slot"], 4),
            (spec["shared_support"], PAGE),
            (spec["support_state"], PAGE),
            (spec["zero_page"], PAGE),
            (spec["channel_control"], 0x40),
        ):
            backend._clean_dva_range(address, size)
    for index in range(graph_slot_count):
        for address in (
                DISPATCH_A + index * 4,
                DISPATCH_B + index * 4,
                STATUS_A + index * 0x10,
                STATUS_B + index * 0x10):
            backend._clean_dva_range(address, 8)
    if status_addresses is not None:
        for ordinal in range(int(item_capacity)):
            status_spec = {}
            _apply_status_addresses(
                status_spec, ordinal, status_addresses)
            for address in (
                    status_spec["status_a"], status_spec["status_b"]):
                backend._clean_dva_range(address, 8)
    backend.u.inst("dsb osh; tlbi vmalle1os; dsb osh; isb")

    # The client graph owns an independent UAT object.  Walk its low root
    # directly so this assertion cannot observe another UAT object's stale
    # context-table cache.
    for spec in queue_layout:
        low = client_space.uat.iotranslate_root(
            client_space.uat.ttbr0_base, spec["context_low"], PAGE)
        high = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, spec["context_high"], PAGE)
        if not low or not high or low[0][0] == high[0][0]:
            raise RuntimeError(
                "compute queue-context low/high views are not distinct")
        if any(_physical_read(backend, low[0][0], PAGE)):
            raise RuntimeError("compute queue-context low view is not blank")
    print(
        "COMPUTE built exact direct graph: queue %#x descriptor %#x "
        "scheduler %#x; context-2 low/firmware-high queue views PA %#x/%#x; "
        "context-0 queue alias=%d" %
        (initial["queue"], initial["descriptor"], initial["scheduler"],
         low[0][0], high[0][0],
         alias_context0_queue),
        flush=True,
    )
    queues[0].workload_queues = queues
    queues[0].initial_spec = initial
    return queues[0]


def stage_built(backend, queue, group_number=1, require_virgin=True):
    """Publish a prepared initial CL2 command and return its live fence."""
    entry = backend.channels.by_name("CL_2")
    if entry is None:
        raise RuntimeError("source world exposes no CL_2 channel")
    if int(entry["ring_addr"]) != OUTER_RING:
        raise RuntimeError(
            "CL_2 ring is %#x, expected %#x" %
            (entry["ring_addr"], OUTER_RING))
    before_channel = backend.channels.counters(entry)
    if require_virgin and before_channel != [0, 0, 0]:
        raise RuntimeError("CL_2 is not virgin: %r" % before_channel)
    if (not require_virgin and
            (before_channel[0] != before_channel[2] or
             before_channel[1] != before_channel[2])):
        raise RuntimeError(
            "CL_2 previous workload is not retired: %r" % before_channel)

    initial = getattr(queue, "initial_spec", _queue_addresses(0))
    published = backend.submitter.stage(
        entry, queue,
        (initial["descriptor"], initial["optional"], initial["event"]),
        group_number=int(group_number),
        slot=0 if require_virgin else None,
        first_submit=True,
        kind="compute",
        announce=False,
        event_counter_low=2,
    )
    slot_address = (
        entry["ring_addr"] +
        int(published["slot"]) * g17p.RING_SLOT_SIZE)
    for address, size in (
        (initial["item_ring"], 0x18),
        (initial["pointers"], 0x80),
        (initial["event"], compute.COMPUTE_EVENT_SIZE),
        (slot_address, g17p.RING_SLOT_SIZE),
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
        name="initial compute workload",
    )
    if fence.signaled():
        raise RuntimeError("initial compute fence signaled before its doorbell")

    backend.submitter.notify(WORK_DOORBELL_CHANNEL)
    return {
        "work_queue": queue,
        "entry": entry,
        "publication": published,
        "fence_object": fence,
    }


def submit_built(front, backend, client, timeout=0.100, queue=None):
    """Publish an already built client graph and require exact add3 output."""
    if queue is None:
        queue = build_firmware_graph(
            backend, client["terminator"], client["space"],
            indirect_dispatch=client.get("indirect_dispatch", False),
            resource_base=client.get("resource_base", RESOURCE),
            cdm_base=client.get("cdm_base", CDM))

    output_pa = client["output_pa"]
    before = _physical_read(backend, output_pa, 256)
    if any(before):
        raise RuntimeError("compute output changed before its work notification")
    staged = stage_built(backend, queue)
    entry = staged["entry"]
    published = staged["publication"]
    fence = staged["fence_object"]

    deadline = time.monotonic() + timeout
    after = before
    while time.monotonic() < deadline:
        after = _physical_read(backend, output_pa, 256)
        if after != before:
            break
        if backend.event_pump is not None:
            backend.event_pump()
        time.sleep(0.0001)
    queue_state = queue.indices()
    channel_state = backend.channels.counters(entry)
    if after == before:
        raise RuntimeError(
            "CL2 produced no output: queue=%r channel=%r publication=%r" %
            (queue_state, channel_state, published))
    fence.wait(timeout=timeout, event_pump=backend.event_pump)
    fence_state = fence.snapshot()
    actual = list(struct.unpack("<64f", after))
    if actual != client["expected"]:
        mismatch = next(
            index for index, pair in enumerate(zip(actual, client["expected"]))
            if pair[0] != pair[1])
        raise RuntimeError(
            "CL2 output mismatch at %d: got %r expected %r" %
            (mismatch, actual[mismatch], client["expected"][mismatch]))
    print(
        "COMPUTE PASS: exact 64-float add3 output at DVA %#x PA %#x; "
        "queue=%r channel=%r" %
        (client["outputs"][0]["dva"], output_pa,
         queue_state, channel_state),
        flush=True,
    )
    return {
        "output_dva": client["outputs"][0]["dva"],
        "output_pa": output_pa,
        "actual": actual,
        "queue": queue_state,
        "channel": channel_state,
        "fence_object": fence,
        "fence": fence_state,
    }


def stage_next_workload(
        backend, client, queue, ordinal, before_publish=None,
        after_publish=None,
        require_previous_retired=True, notify=True,
        input_a_dependency=None,
        fresh_command3_style=False, persistent_runtime_queue=False,
        persistent_startup_queue=False,
        persistent_runtime_optional_once=False,
        persistent_runtime_fresh_descriptors=False,
        persistent_runtime_fresh_events=False,
        fast_sequential=False, persistent_runtime_recycle_interval=None,
        persistent_runtime_context_record_count=None,
        persistent_runtime_alternating_contexts=False,
        persistent_runtime_preserve_context_reuse=False,
        persistent_runtime_optional_skip_ordinals=(),
        strict_release_publish=False):
    """Build and publish one later dispatch, optionally without notifying."""
    if ordinal < 1:
        raise ValueError("later compute workload ordinals start at one")
    indirect_runtime = bool(client.get("indirect_dispatch"))
    if indirect_runtime and persistent_runtime_optional_once:
        raise ValueError(
            "indirect runtime commands require command-local optional records")
    prepare_workload = client.get("prepare_workload")
    if prepare_workload is None:
        workload = prepare_client_workload(
            client, ordinal, input_a_dependency=input_a_dependency)
    else:
        workload = prepare_workload(ordinal)
    expected_values = workload.get("expected")
    expected = (
        b"" if expected_values is None else
        bytes(expected_values) if isinstance(expected_values, (bytes, bytearray))
        else struct.pack("<64f", *expected_values))
    output_pa = workload.get("output_pa")
    before = (
        b"" if output_pa is None else
        bytes(len(expected)) if fast_sequential else
        _physical_read(backend, output_pa, len(expected)))
    if any(before):
        raise RuntimeError("compute output %d did not start zero" % ordinal)

    indirect_second = bool(indirect_runtime and ordinal == 1)
    slot = (
        1 if (indirect_second and persistent_runtime_queue and
              persistent_startup_queue) else
        0 if persistent_runtime_queue and persistent_startup_queue else
        1 if persistent_runtime_queue else
        _queue_slot(ordinal, fresh_command3_style=fresh_command3_style))
    spec = _work_addresses(
        ordinal, fresh_command3_style=fresh_command3_style)
    context_item_index = 0
    context_grid = spec["grid"]
    optional_first_submit = True
    if persistent_runtime_queue:
        persistent = (
            _indirect_runtime_addresses(ordinal)
            if indirect_runtime else _queue_addresses(1))
        transport = (
            persistent if indirect_runtime else
            _queue_addresses(1) if indirect_second else
            _queue_addresses(0) if persistent_startup_queue else persistent)
        context_item_index = (
            ordinal if persistent_startup_queue else ordinal - 1)
        if (persistent_runtime_alternating_contexts
                and not persistent_startup_queue):
            raise ValueError(
                "alternating contexts currently require the startup queue")
        if persistent_runtime_recycle_interval is not None:
            interval = int(persistent_runtime_recycle_interval)
            if interval < 1:
                raise ValueError("persistent queue recycle interval must be positive")
            context_item_index %= interval
        for name in (
                "queue", "pointers", "item_ring", "job_list",
                "context_low", "context_high", "channel_control", "grid",
                "uuid", "shared_support", "support_state", "zero_page",
                "context_id", "dispatch_a", "dispatch_b", "status_a",
                "status_b", "optional_field_32", "optional_field_46",
                "optional_field_56", "qctx_flags", "qctx_word_220",
                "qctx_word_338"):
            spec[name] = persistent[name]
        for name in (
                "queue", "pointers", "item_ring", "job_list",
                "context_low", "context_high", "channel_control", "grid"):
            spec[name] = transport[name]
        context_grid = spec["grid"]
        if persistent_runtime_alternating_contexts:
            context = _queue_addresses(ordinal & 1)
            spec["context_low"] = context["context_low"]
            spec["context_high"] = context["context_high"]
            context_grid = context["grid"]
            context_item_index = ordinal // 2
        spec["support_style"] = 1
        spec["channel_control_style"] = 1
        spec["optional_submission"] = (
            persistent["optional_submission"] + context_item_index)
        if persistent_runtime_fresh_descriptors:
            descriptor_slot = ordinal % DESCRIPTOR_RING_RECORDS
            spec["descriptor"] = (
                DESCRIPTOR + descriptor_slot * DESCRIPTOR_STRIDE)
            spec["descriptor_low"] = (
                DESCRIPTOR_LOW + descriptor_slot * DESCRIPTOR_STRIDE)
        if persistent_runtime_fresh_events and not indirect_runtime:
            spec["event"] = RUNTIME_EVENT_BASE + ordinal * EVENT_STRIDE
    if indirect_runtime:
        spec.update(_indirect_runtime_addresses(ordinal))
        context_grid = spec["grid"]
        context_item_index = ordinal
        optional_first_submit = False
    _apply_status_addresses(
        spec, ordinal, client.get("status_addresses"))
    _apply_user_timestamp_addresses(
        spec, ordinal, client.get("user_timestamp_addresses"))
    descriptor = spec["descriptor"]
    descriptor_low = spec["descriptor_low"]
    optional = spec["optional"]
    event = spec["event"]
    shared_support = spec["shared_support"]
    if os.getenv("G17P_STAGE_FINGERPRINT") == "1":
        print(
            "COMPUTE STAGE QUEUE +0x94 entry=%#x" % struct.unpack(
                "<I", backend._read_dva(
                    spec["queue"] + g17p.QUEUE_UNK_94, 4))[0],
            flush=True,
        )
    scheduler, scheduler_slot, scheduler_work_id = (
        _scheduler_for_ordinal(spec, ordinal))
    refreshed = _refresh_runtime_slot(
        backend, spec, slot, ordinal,
        scheduler, scheduler_slot, scheduler_work_id,
        persistent_static=(
            fast_sequential and persistent_runtime_queue and ordinal > 1))
    switches_queue_backing = indirect_second
    if switches_queue_backing:
        pointers = bytearray(0x80)
        base_pointers = g17p.build_queue_pointers()
        pointers[:len(base_pointers)] = base_pointers
        for offset in (
                g17p.QUEUE_PTR_DONE,
                g17p.QUEUE_PTR_READ,
                g17p.QUEUE_PTR_WRITE):
            struct.pack_into("<I", pointers, offset, 3)
        struct.pack_into("<I", pointers, 0x60, 0x500)
        backend._write_dva(spec["pointers"], pointers)
        item_ring = bytearray(QUEUE_PAIR_OBJECT_STRIDE)
        retained = _indirect_first_addresses()
        struct.pack_into(
            "<3Q", item_ring, 0,
            retained["descriptor"], retained["optional"], retained["event"])
        backend._write_dva(spec["item_ring"], item_ring)

        # Keep firmware-owned completion state from command 1 while moving the
        # host-owned queue links to the next native backing pair.
        queue_record = bytearray(backend._read_dva(
            spec["queue"], g17p.QUEUE_RECORD_STRIDE))
        for offset, value in (
                (g17p.QUEUE_POINTERS_ADDR, spec["pointers"]),
                (g17p.QUEUE_RING_ADDR, spec["item_ring"]),
                (g17p.QUEUE_JOB_LIST_ADDR, spec["job_list"]),
                (g17p.QUEUE_CONTEXT_ADDR, spec["channel_control"])):
            struct.pack_into("<Q", queue_record, offset, value)
        struct.pack_into(
            "<I", queue_record, g17p.QUEUE_UUID, spec["uuid"])
        backend._write_dva(spec["queue"], queue_record)
        for address, size in (
                (spec["pointers"], 0x80),
                (spec["item_ring"], QUEUE_PAIR_OBJECT_STRIDE),
                (spec["queue"], g17p.QUEUE_RECORD_STRIDE)):
            backend._clean_dva_range(address, size)
        backend.space.flush()
        backend.u.inst("dsb sy")
    queues = getattr(queue, "workload_queues", (queue,))
    if not switches_queue_backing and slot >= len(queues):
        raise RuntimeError("compute queue slot %d was not constructed" % slot)
    work_queue = (
        G17PQueue(backend._read_dva, spec["queue"], spec["grid"])
        if indirect_runtime else queues[slot])
    recycle_queue = (
        persistent_runtime_queue and
        persistent_runtime_recycle_interval is not None and
        ordinal % int(persistent_runtime_recycle_interval) == 0)
    if recycle_queue:
        previous = work_queue.indices()
        if not (previous["done"] == previous["read"] ==
                previous["write"]):
            raise RuntimeError(
                "cannot recycle active compute queue at ordinal %d: %r" %
                (ordinal, previous))
        for offset in (
                g17p.QUEUE_PTR_DONE,
                g17p.QUEUE_PTR_READ,
                g17p.QUEUE_PTR_WRITE):
            backend._write_dva(spec["pointers"] + offset, bytes(4))
            backend._clean_dva_range(spec["pointers"] + offset, 4)
        backend._write_dva(
            spec["queue"] + g17p.QUEUE_GPU_RPTR2, bytes(4))
        backend._clean_dva_range(
            spec["queue"] + g17p.QUEUE_GPU_RPTR2, 4)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "COMPUTE recycled idle persistent queue at workload %d from %r "
            "to 0/0/0" % (ordinal, previous),
            flush=True,
        )
    in_place = (not persistent_runtime_queue and int(ordinal) >= 3
                and not spec.get("fresh_lifetime", False))
    context_id = spec["context_id"]
    register_builder = client.get("register_builder")
    registers = (
        _registers_for_workload(
            ordinal, metadata_ordinal=spec.get("metadata_ordinal"),
            command_slot=workload["slot"],
            indirect_dispatch=client.get("indirect_dispatch", False),
            resource_base=client.get("resource_base", RESOURCE),
            cdm_base=client.get("cdm_base", CDM))
        if register_builder is None else
        register_builder(ordinal, spec, workload))
    descriptor_body = compute.build_compute_descriptor(
            registers,
            scheduler_record=scheduler,
            low_alias=descriptor_low,
            cdm_terminator=workload["terminator"],
            submit_sequence=_work_ordinal(ordinal),
            context_id=context_id,
            grid_index=spec["grid"],
            dispatch_a=spec["dispatch_a"],
            dispatch_b=spec["dispatch_b"],
            status_a=spec["status_a"],
            status_b=spec["status_b"],
            user_timestamp_start=spec.get("user_timestamp_start", 0),
            user_timestamp_end=spec.get("user_timestamp_end", 0),
            zero_page=spec["zero_page"],
            shared_control=shared_support,
            protection_index=1,
            support_control=0xE0A00001,
            support_flags=0,
            work_ordinal=_work_ordinal(ordinal),
            queue_submission=ordinal + 1,
            queue_ordinal=0,
            submission_index=ordinal + 1,
            sampler_array=client.get("sampler_array", 0),
            sampler_count=client.get("sampler_count", 0),
        )
    backend._write_dva(descriptor, descriptor_body[:DESCRIPTOR_BODY_SIZE])
    include_optional = not (
        persistent_runtime_queue and persistent_runtime_optional_once
        and (persistent_startup_queue or ordinal > 1))
    if ordinal in persistent_runtime_optional_skip_ordinals:
        include_optional = False
    if include_optional or not fast_sequential:
        backend._write_dva(
            optional,
            compute.build_compute_optional(
                spec["context_low"],
                spec["context_high"],
                grid_index=context_grid,
                submission_ordinal=spec["optional_submission"],
                shared_control=shared_support,
                channel_control=spec["channel_control"],
                uuid=spec["uuid"],
                field_46=spec["optional_field_46"],
                field_1e=2,
                field_32=spec["optional_field_32"],
                field_56=spec["optional_field_56"],
                field_5e=2,
                first_submit=optional_first_submit,
                item_index=0,
            ),
        )
    backend._write_dva(event, bytes(0x40))
    descriptor_step = (descriptor - DESCRIPTOR) // 0x20
    context_item = compute.build_compute_queue_context_item(
            descriptor,
            spec["queue"],
            context_grid,
            flags_200=spec["qctx_flags"],
            word_220=spec["qctx_word_220"],
            word_330=0,
            word_338=spec["qctx_word_338"],
            word_350=0x000110038001A002 + descriptor_step,
            word_358=0x000020038001A03B + descriptor_step,
            word_378=0x003FFFFFFFFFFFFF,
            item_index=context_item_index,
        )
    context_item_address = (
        spec["context_high"]
        + compute.compute_queue_context_record_offset(
            context_item_index,
            record_count=persistent_runtime_context_record_count))
    if persistent_runtime_queue:
        if (persistent_runtime_preserve_context_reuse and
                context_item_index >= (
                    compute.COMPUTE_QUEUE_CONTEXT_RECORDS
                    if persistent_runtime_context_record_count is None else
                    int(persistent_runtime_context_record_count))):
            context_item = compute.update_compute_queue_context_item(
                backend._read_dva(
                    context_item_address,
                    compute.COMPUTE_QUEUE_CONTEXT_RECORD_SIZE),
                context_item,
            )
        backend._write_dva(context_item_address, context_item)
        context_page = context_item_address & ~(PAGE - 1)
        context_clean = (context_page, PAGE)
        if (not fast_sequential and backend._read_dva(
                context_item_address, len(context_item)) != context_item):
            raise RuntimeError(
                "compute queue-context record %#x did not read back" %
                context_item_address)
    else:
        backend._write_dva(
            spec["context_high"],
            compute.build_compute_queue_context(
                descriptor,
                spec["queue"],
                spec["grid"],
                flags_200=spec["qctx_flags"],
                word_220=spec["qctx_word_220"],
                word_330=0,
                word_338=spec["qctx_word_338"],
                word_350=0x000110038001A002 + descriptor_step,
                word_358=0x000020038001A03B + descriptor_step,
                word_378=0x003FFFFFFFFFFFFF,
            ),
        )
        context_clean = (
            spec["context_high"], compute.COMPUTE_QUEUE_CONTEXT_SIZE)
    retained_context_queue = None
    if indirect_second:
        # Native command 2 retains command 1's context record, but both
        # records name the newly selected queue.  Change only that host-owned
        # queue pointer; the rest of record 0 contains firmware state.
        retained_context_queue = (
            spec["context_high"]
            + compute.compute_queue_context_record_offset(0)
            + 0x18)
        backend._write_dva(
            retained_context_queue, struct.pack("<Q", spec["queue"]))
    starts_queue_lifetime = (
        not persistent_runtime_queue or
        (ordinal == 1 and not persistent_startup_queue))
    if starts_queue_lifetime:
        backend._write_dva(spec["queue"], g17p.build_queue_record(
            spec["pointers"], spec["item_ring"], spec["job_list"],
            spec["channel_control"], uuid=spec["uuid"], priority=2,
            prio5=2, unk_2c=2, unk_38=0, unk_94=0,
            sentinel_size=2,
        ))
    elif indirect_second:
        backend._write_dva(
            spec["queue"] + g17p.QUEUE_UUID,
            struct.pack("<I", spec["uuid"]),
        )
    clean_ranges = [
        (descriptor, DESCRIPTOR_BODY_SIZE),
        (event, 0x40),
        context_clean,
    ]
    if retained_context_queue is not None:
        clean_ranges.append((retained_context_queue, 8))
    if indirect_second and not starts_queue_lifetime:
        clean_ranges.append((spec["queue"] + g17p.QUEUE_UUID, 4))
    if include_optional or not fast_sequential:
        clean_ranges.append((optional, compute.COMPUTE_OPTIONAL_SIZE))
    clean_ranges.extend(refreshed)
    for address, size in clean_ranges:
        backend._clean_dva_range(address, size)

    if starts_queue_lifetime:
        backend._clean_dva_range(spec["queue"], g17p.QUEUE_RECORD_STRIDE)

    if (ordinal == 3 and not persistent_runtime_queue
            and not spec.get("fresh_lifetime", False)):
        previous = work_queue.indices()
        if not (previous["done"] == previous["read"] ==
                previous["write"] == 3):
            raise RuntimeError(
                "command-four queue lifetime did not retire cleanly: %r" %
                previous)
        backend._write_dva(
            spec["pointers"] + g17p.QUEUE_PTR_DONE, bytes(4))
        backend._write_dva(
            spec["pointers"] + g17p.QUEUE_PTR_READ, bytes(4))
        print(
            "COMPUTE reset native command-four queue lifetime to 0/0/3",
            flush=True,
        )

    if before_publish is not None:
        before_publish()

    entry = backend.channels.by_name("CL_2")
    channel_before = backend.channels.counters(entry)
    if (require_previous_retired and
            (channel_before[0] != channel_before[2] or
             channel_before[1] != channel_before[2])):
        raise RuntimeError(
            "CL2 previous workload is not retired before ordinal %d: %r" %
            (ordinal, channel_before))

    items = (
        (descriptor, optional, event)
        if include_optional else (descriptor, event))
    item_count = len(items)
    queue_before = work_queue.indices()
    advertised_head = (
        queue_before["write"]
        if in_place else queue_before["write"] + item_count)
    saved_deferred = backend.submitter.deferred_producers
    if strict_release_publish:
        if saved_deferred is not None:
            raise RuntimeError(
                "strict compute publication cannot nest deferred producers")
        backend.submitter.deferred_producers = []
    try:
        published = backend.submitter.stage(
            entry,
            work_queue,
            items,
            group_number=ordinal + 1,
            first_submit=(advertised_head == 3),
            kind="compute",
            in_place=in_place,
            announce=False,
            event_counter_low=2,
            queue_indices=(queue_before if fast_sequential else None),
            consumers_before=(channel_before[:2] if fast_sequential else None),
            slot=(channel_before[2] if fast_sequential else None),
        )
        deferred_producers = (
            list(backend.submitter.deferred_producers)
            if strict_release_publish else [])
    finally:
        if strict_release_publish:
            backend.submitter.deferred_producers = saved_deferred
    if strict_release_publish and len(deferred_producers) != 1:
        raise RuntimeError(
            "strict compute publication deferred %d producers" %
            len(deferred_producers))
    slot_address = (
        entry["ring_addr"] + published["slot"] * g17p.RING_SLOT_SIZE)
    first_entry = (
        published["write_after"] - item_count
        if not in_place else published["write_before"] - item_count)
    for address, size in (
        (work_queue.item_ring + first_entry * g17p.ITEM_RING_ENTRY_SIZE,
         item_count * g17p.ITEM_RING_ENTRY_SIZE),
        (work_queue.pointers_addr, 0x80),
        (event, 0x40),
        (slot_address, g17p.RING_SLOT_SIZE),
    ):
        backend._clean_dva_range(address, size)
    backend.space.flush()
    if strict_release_publish:
        # Publish payload and slot before making the producer visible.  Without
        # this release boundary, a reused slot can be observed with its old
        # contents while cache maintenance for the producer completes first.
        backend.u.inst("dsb sy")
        producer_address, producer_body = deferred_producers[0]
        if os.getenv("G17P_STAGE_FINGERPRINT") == "1":
            print(
                "COMPUTE STAGE QUEUE +0x94 pre-producer=%#x" % struct.unpack(
                    "<I", backend._read_dva(
                        spec["queue"] + g17p.QUEUE_UNK_94, 4))[0],
                flush=True,
            )
        backend._write_dva(producer_address, producer_body)
        backend._clean_dva_range(producer_address, len(producer_body))
        backend.u.inst("dsb sy")
    else:
        for address in entry["state_addrs"]:
            backend._clean_dva_range(address, 4)
        backend.u.inst("dsb sy")
    if os.getenv("G17P_STAGE_FINGERPRINT") == "1":
        firmware_objects = {
            "descriptor": (descriptor, DESCRIPTOR_BODY_SIZE),
            "optional": (optional, compute.COMPUTE_OPTIONAL_SIZE),
            "event": (event, compute.COMPUTE_EVENT_SIZE),
            "queue_context": (
                context_item_address, compute.COMPUTE_QUEUE_CONTEXT_RECORD_SIZE),
            "queue": (spec["queue"], g17p.QUEUE_RECORD_STRIDE),
            "queue_pointers": (spec["pointers"], 0x80),
            "item_ring": (
                work_queue.item_ring + first_entry * g17p.ITEM_RING_ENTRY_SIZE,
                item_count * g17p.ITEM_RING_ENTRY_SIZE),
            "outer_ring_slot": (slot_address, g17p.RING_SLOT_SIZE),
            "scheduler": (scheduler, 0x100),
            "scheduler_slot": (scheduler_slot, 4),
            "shared_support": (shared_support, 0x100),
            "support_state": (spec["support_state"], 0x40),
            "channel_control": (spec["channel_control"], 0x40),
            "job_list": (spec["job_list"], g17p.JOB_LIST_SIZE),
            "dispatch_a": (spec["dispatch_a"], 8),
            "dispatch_b": (spec["dispatch_b"], 8),
            "status_a": (spec["status_a"], 8),
            "status_b": (spec["status_b"], 8),
        }
        bodies = {
            "firmware." + name: backend._read_dva(address, size)
            for name, (address, size) in firmware_objects.items()
        }
        command_slot = int(workload["slot"])
        client_names = [
            "resource" if command_slot == 0 else "resource_%02d" % command_slot,
            "cdm" if command_slot == 0 else "cdm_%02d" % command_slot,
            "shader" if command_slot == 0 else "shader_%02d" % command_slot,
            "input_a" if command_slot < 2 else "input_a_%02d" % command_slot,
            "input_b" if command_slot < 2 else "input_b_%02d" % command_slot,
            "output" if command_slot == 0 else "output_%02d" % command_slot,
        ]
        for name in client_names:
            _dva, pa, size = client["objects"][name]
            bodies["client." + name] = client["space"].read(pa, size)
        print(
            "COMPUTE STAGE FINGERPRINT %s" % json.dumps({
                name: hashlib.sha256(bytes(body)).hexdigest()
                for name, body in sorted(bodies.items())
            }, sort_keys=True),
            flush=True,
        )
        print(
            "COMPUTE STAGE QUEUE HEX %s" %
            bodies["firmware.queue"].hex(),
            flush=True,
        )
    if after_publish is not None:
        after_publish()
    completion_before = {
        "event": backend._read_dva(event, compute.COMPUTE_EVENT_SIZE),
        "status_a": backend._read_dva(spec["status_a"], 8),
        "status_b": backend._read_dva(spec["status_b"], 8),
    }
    fence = G17PQueueFence(
        backend.submitter,
        entry,
        work_queue,
        published,
        status_read=lambda address=spec["status_b"]: backend._read_dva(
            address, 8),
        status_initial=completion_before["status_b"],
        name="compute workload %d" % ordinal,
    )
    if notify:
        backend.submitter.notify(WORK_DOORBELL_CHANNEL)

    return {
        "ordinal": ordinal,
        "workload": workload,
        "expected": expected,
        "before": before,
        "work_queue": work_queue,
        "entry": entry,
        "channel_before": channel_before,
        "publication": published,
        "completion_addresses": {
            "event": event,
            "status_a": spec["status_a"],
            "status_b": spec["status_b"],
        },
        "completion_before": completion_before,
        "fence": fence,
    }


def await_next_workload(backend, prepared, timeout=0.100):
    """Require exact output and retirement from a staged later dispatch."""
    ordinal = prepared["ordinal"]
    workload = prepared["workload"]
    expected = prepared["expected"]
    before = prepared["before"]
    work_queue = prepared["work_queue"]
    entry = prepared["entry"]
    channel_before = prepared["channel_before"]
    published = prepared["publication"]
    fence = prepared["fence"]

    deadline = time.monotonic() + timeout
    after = before
    queue_state = work_queue.indices()
    channel_state = backend.channels.counters(entry)
    while time.monotonic() < deadline:
        after = _physical_read(backend, workload["output_pa"], len(expected))
        fence_signaled = fence.signaled()
        queue_state = work_queue.indices()
        channel_state = backend.channels.counters(entry)
        if after == expected and fence_signaled:
            break
        if backend.event_pump is not None:
            backend.event_pump()
        time.sleep(0.0001)

    changed = sum(left != right for left, right in zip(before, after))
    if after != expected:
        queue_record = g17p.parse_queue_record(backend._read_dva(
            work_queue.address, g17p.QUEUE_RECORD_STRIDE))
        raise RuntimeError(
            "CL2 workload %d produced no exact output: changed=%d queue=%r "
            "queue_record=%r channel=%r publication=%r" %
            (ordinal, changed, queue_state, queue_record, channel_state,
             published))
    if not all(
            g17p.producer_reached(start, current, published["producer"])
            for start, current in zip(channel_before[:2], channel_state[:2])):
        raise RuntimeError(
            "CL2 workload %d wrote output but did not retire its channel: %r" %
            (ordinal, channel_state))
    fence_state = fence.snapshot()
    if not fence_state["signaled"]:
        raise RuntimeError(
            "CL2 workload %d produced output without signaling its fence: %r" %
            (ordinal, fence_state))
    completion_after = {
        name: backend._read_dva(
            prepared["completion_addresses"][name], len(body))
        for name, body in prepared["completion_before"].items()
    }
    completion_changes = {
        name: sum(left != right for left, right in zip(
            prepared["completion_before"][name], body))
        for name, body in completion_after.items()
    }
    completion_values = {
        name: int.from_bytes(completion_after[name], "little")
        for name in ("status_a", "status_b")
    }
    event_changed_offsets = [
        offset for offset, (left, right) in enumerate(zip(
            prepared["completion_before"]["event"],
            completion_after["event"]))
        if left != right
    ]
    print(
        "COMPUTE REPEAT %02d PASS: exact output DVA %#x PA %#x changed=%d "
        "queue=%r channel=%r fence_sequence=%d completion_changes=%r "
        "completion_values=%r "
        "event_changed_offsets=%r" %
        (ordinal, workload["output_dva"], workload["output_pa"], changed,
         queue_state, channel_state, fence.sequence, completion_changes,
         completion_values,
         event_changed_offsets),
        flush=True,
    )
    return {
        "workload": workload,
        "changed": changed,
        "queue": queue_state,
        "channel": channel_state,
        "publication": published,
        "fence_object": fence,
        "fence": fence_state,
        "completion_addresses": prepared["completion_addresses"],
        "completion_before": prepared["completion_before"],
        "completion_after": completion_after,
        "completion_changes": completion_changes,
        "completion_values": completion_values,
        "event_changed_offsets": event_changed_offsets,
    }


def submit_next_workload(
        backend, client, queue, ordinal, timeout=0.100,
        before_publish=None, after_publish=None,
        fresh_command3_style=False, persistent_runtime_queue=False,
        persistent_startup_queue=False,
        persistent_runtime_optional_once=False,
        persistent_runtime_fresh_descriptors=False,
        persistent_runtime_fresh_events=False,
        fast_sequential=False, persistent_runtime_recycle_interval=None,
        persistent_runtime_context_record_count=None,
        persistent_runtime_alternating_contexts=False,
        persistent_runtime_preserve_context_reuse=False,
        persistent_runtime_optional_skip_ordinals=(),
        strict_release_publish=False):
    """Publish one later dispatch on live CL2 and require its exact output."""
    prepared = stage_next_workload(
        backend, client, queue, ordinal,
        before_publish=before_publish,
        after_publish=after_publish,
        require_previous_retired=True,
        notify=True,
        fresh_command3_style=fresh_command3_style,
        persistent_runtime_queue=persistent_runtime_queue,
        persistent_startup_queue=persistent_startup_queue,
        persistent_runtime_optional_once=persistent_runtime_optional_once,
        persistent_runtime_fresh_descriptors=(
            persistent_runtime_fresh_descriptors),
        persistent_runtime_fresh_events=persistent_runtime_fresh_events,
        fast_sequential=fast_sequential,
        persistent_runtime_recycle_interval=(
            persistent_runtime_recycle_interval),
        persistent_runtime_context_record_count=(
            persistent_runtime_context_record_count),
        persistent_runtime_alternating_contexts=(
            persistent_runtime_alternating_contexts),
        persistent_runtime_preserve_context_reuse=(
            persistent_runtime_preserve_context_reuse),
        persistent_runtime_optional_skip_ordinals=(
            persistent_runtime_optional_skip_ordinals),
        strict_release_publish=strict_release_publish,
    )
    return await_next_workload(backend, prepared, timeout=timeout)


def submit_once(front, backend, timeout=0.100):
    """Build, publish, and require the exact add3 result."""
    return submit_built(
        front, backend, build_client_graph(backend), timeout=timeout)
