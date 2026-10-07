#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small, hardware-derived helpers for G17P work queues."""

import struct


ITEM_RECORD_BYTES = {
    0x00: 0x9C0,   # geometry work
    0x01: 0x2240,  # fragment work
    0x0E: 0x40,    # one event-ring record
    0x0F: 0xC0,    # one optional-item record
}


def _value(raw):
    return int(raw, 0) if isinstance(raw, str) else int(raw)


def queue_state_words(queue):
    """Return the completion, read, and write indices from a captured queue."""
    words = queue.get("state_u32") or {}
    if all(key in words for key in ("0x00", "0x30", "0x40")):
        return tuple(_value(words[key]) for key in ("0x00", "0x30", "0x40"))

    raw = bytes.fromhex(queue["state_hex"])
    return tuple(struct.unpack_from("<I", raw, offset)[0]
                 for offset in (0x00, 0x30, 0x40))


def pending_entry_span(queue):
    """Return the half-open range of item-ring entries pending at capture."""
    complete, read, write = queue_state_words(queue)
    if complete != read:
        raise ValueError(
            "capture has different completion and read indices (%d != %d)"
            % (complete, read)
        )
    if write < read:
        raise ValueError(
            "wrapped item-ring capture is not supported (%d -> %d)" % (read, write)
        )
    return read, write


def item_record_size(selector):
    try:
        return ITEM_RECORD_BYTES[int(selector)]
    except KeyError as error:
        raise ValueError("unknown G17P item selector %#x" % int(selector)) from error
