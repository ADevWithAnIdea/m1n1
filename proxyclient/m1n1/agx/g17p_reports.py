# SPDX-License-Identifier: MIT
"""Read-only snapshots of the G17P channel-13 firmware report ring.

State pointers zero and two name split host/firmware counters. Pointer one
names the first record buffer, not a third counter. Its 0x4800-byte extent
before the other buffer holds 256 records of 0x48 bytes. Record payloads stay
opaque until their individual semantics have been qualified on Neo.
"""

import struct


CAPACITY = 256
RECORD_SIZE = 0x48
PEER_OFFSET = 0x20


def build_class1_registration_receipt(sequence, first_object, operand_table,
                                      slot_offset=0x580, count=0x28):
    """Expected 0x28-byte transaction prefix of a mixed class-1 receipt.

    This identifies a control transaction, not command completion or recovery.
    The full 0x48-byte ring record is retained by the reader. Bytes +0x28..47
    differ across successful executions and are not matched as transaction
    fields. Unknown classes or differing transaction fields remain rejected.
    """
    out = bytearray(0x28)
    struct.pack_into("<IIIQQQI", out, 0, 13, 1, int(sequence),
                     int(first_object), int(operand_table),
                     int(operand_table) + int(slot_offset), int(count))
    return bytes(out)


def _unchanged_startup_report(row, ring, before):
    """The measured initial type-13 record predates caller publication.

    This narrow exemption is not a decoder or a generic type-13 success rule.
    Require the complete pre-kick one-record window and unchanged slot/body,
    backing, and consumer. Later type-13 records remain unsupported.
    """
    if not before or before.get("error") or before.get("truncated"):
        return False
    previous = before.get("records", ())
    counters = before.get("counters", ())
    current = ring.get("counters", ())
    if (len(previous) != 1 or len(counters) != 2 or len(current) != 2 or
            before.get("pending") != 1 or row.get("slot") != 0 or
            previous[0].get("slot") != 0 or
            previous[0].get("record_hex") != row.get("record_hex") or
            before.get("records_address") != ring.get("records_address") or
            before.get("other_ring") != ring.get("other_ring")):
        return False
    return (counters[0].get("host") == current[0].get("host") == 0 and
            counters[0].get("firmware") == 1 and
            counters[0].get("address") == current[0].get("address") and
            1 <= current[0].get("firmware", -1) < CAPACITY)


def unhandled_channel13(snapshot, owned_descriptors=(), *, startup_snapshot=None,
                        owned_control_receipts=()):
    """Reject unsupported reports before a submission's software fence signals.

    Type 1 accompanies qualified Neo completion. Type 7 was observed alongside
    corrupt outputs despite successful queue/status retirement. Its +0x28
    qword names our fragment descriptor in that observation, unlike M5's
    layout. Matching an owned pointer attributes the report, not its cause.
    Neo's ordinary opening emits (13,1,0) before caller publication. An exact
    unchanged pre-work record is startup traffic, not a failure of this draw.
    Other unknown types and incomplete snapshots still require quarantine:
    there is no qualified service/recovery protocol here. This never ACKs.
    """
    owned = set(owned_descriptors)
    receipts = list(owned_control_receipts)
    if any(len(body) != 0x28 or struct.unpack_from("<II", body) != (13, 1)
           for body in receipts):
        raise ValueError("invalid owned class-1 registration receipt")
    failures = []
    for channel, ring in snapshot.items():
        if not channel.endswith("_ch13"):
            continue
        if ring.get("error") or ring.get("truncated"):
            failures.append(dict(channel=channel, reason="incomplete-report-snapshot"))
        for row in ring.get("records", ()):
            body = bytes.fromhex(row.get("record_hex", ""))
            if len(body) != RECORD_SIZE:
                failures.append(dict(channel=channel, slot=row.get("slot"),
                                     reason="invalid-report-size"))
                continue
            opcode, = struct.unpack_from("<I", body)
            if opcode == 1:
                continue
            if channel == "primary_ch13" and opcode == 13 and body[:0x28] in receipts:
                # Consume one exact expected transaction locally. A duplicate
                # or a receipt on the other firmware instance stays unknown.
                receipts.remove(body[:0x28])
                continue
            if (struct.unpack_from("<3I", body) == (13, 1, 0) and
                    _unchanged_startup_report(row, ring,
                        (startup_snapshot or {}).get(channel))):
                continue
            failure = dict(channel=channel, slot=row.get("slot"), opcode=opcode,
                           reason="unhandled-firmware-report")
            if opcode == 7:
                descriptor, = struct.unpack_from("<Q", body, 0x28)
                failure.update(reported_descriptor=descriptor,
                               owned_descriptor=descriptor in owned)
            failures.append(failure)
    return failures


def split_counters(read, states):
    result = []
    for index in (0, 2):
        address = int(states[index])
        body = read(address, PEER_OFFSET + 4)
        if len(body) != PEER_OFFSET + 4:
            raise ValueError("short report counter read")
        result.append(dict(address=address, host=struct.unpack_from("<I", body)[0],
                           firmware=struct.unpack_from("<I", body, PEER_OFFSET)[0]))
    return result


def snapshot_channel13(read, states, other_ring, *, limit=16):
    """Copy pending records without consuming credits or inferring execution."""
    if not 1 <= limit <= CAPACITY or len(states) != 3 or not all(states):
        raise ValueError("invalid channel-13 snapshot bounds")
    records = int(states[1])
    if int(other_ring) - records != CAPACITY * RECORD_SIZE:
        raise ValueError("unqualified channel-13 record-buffer layout")
    counters = split_counters(read, states)
    head, tail = counters[0]["host"], counters[0]["firmware"]
    if not 0 <= head < CAPACITY or not 0 <= tail < CAPACITY:
        raise ValueError("report counter outside the qualified modulo-256 ring")
    pending = (tail - head) % CAPACITY
    count = min(pending, limit)
    rows = []
    while len(rows) < count:
        slot = (head + len(rows)) % CAPACITY
        length = min(count - len(rows), CAPACITY - slot)
        body = read(records + slot * RECORD_SIZE, length * RECORD_SIZE)
        if len(body) != length * RECORD_SIZE:
            raise ValueError("short firmware report read")
        for offset in range(length):
            record = body[offset * RECORD_SIZE:(offset + 1) * RECORD_SIZE]
            rows.append(dict(slot=slot + offset, header=struct.unpack_from("<4I", record),
                             record_hex=record.hex()))
    return dict(counters=counters, records_address=records, other_ring=int(other_ring),
                pending=pending, truncated=pending > count, records=rows,
                execution_claim="none; opaque firmware reports")
