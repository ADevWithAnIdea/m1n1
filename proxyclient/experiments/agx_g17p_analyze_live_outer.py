#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize saved native T8140/G17P outer-work recorder artifacts.

The script consumes only JSON records captured from live shared memory.  It
does not connect to hardware or inspect firmware binaries.  Its output keeps
the four 0x18-byte notification subrecords separate and describes queue state
as raw integers, avoiding guesses about scheduler field semantics.
"""

import argparse
import hashlib
import json
import pathlib
import struct


SUBRECORD_SIZE = 0x18


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "trace",
        type=pathlib.Path,
        help="directory containing outer_submissions.jsonl",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="output JSON path (defaults inside the trace directory)",
    )
    return parser.parse_args()


def u64_words(data):
    return list(struct.unpack("<%dQ" % (len(data) // 8), data))


def u32_at(data, offset):
    if len(data) < offset + 4:
        return None
    return struct.unpack_from("<I", data, offset)[0]


def summarize_queue(queue):
    if queue.get("read_error"):
        return {
            "outer_offset": queue["outer_offset"],
            "queue_dva": queue["queue_addr"],
            "read_error": queue["read_error"],
        }

    state = bytes.fromhex(queue["queue_state_hex"])
    inner = bytes.fromhex(queue["inner_ring_hex"])
    return {
        "outer_offset": queue["outer_offset"],
        "queue_dva": queue["queue_addr"],
        "queue_state_dva": queue["queue_state_addr"],
        "inner_ring_dva": queue["inner_ring_addr"],
        "queue_state_u32": {
            "0x00": u32_at(state, 0x00),
            "0x30": u32_at(state, 0x30),
            "0x40": u32_at(state, 0x40),
        },
        "inner_ring_prefix_u64": u64_words(inner[:0x90]),
        "inner_ring_prefix_sha256": hashlib.sha256(inner).hexdigest(),
    }


def summarize_record(record):
    outer = bytes.fromhex(record["outer_hex"])
    subrecords = []
    for offset in range(0, len(outer), SUBRECORD_SIZE):
        first, queue_dva, tail = struct.unpack_from("<QQQ", outer, offset)
        subrecords.append(
            {
                "offset": offset,
                "first_u64": first,
                "queue_dva": queue_dva,
                "tail_u64": tail,
            }
        )

    return {
        "sequence": record["sequence"],
        "entry_index": record["entry_index"],
        "producer_before": record["producer_before"],
        "producer_after": record["producer_after"],
        "outer_dva": record["outer_addr"],
        "outer_subrecords": subrecords,
        "queues": [summarize_queue(queue) for queue in record.get("queues", [])],
    }


def main():
    args = parse_args()
    trace = args.trace.resolve()
    source = trace / "outer_submissions.jsonl"
    records = [json.loads(line) for line in source.read_text().splitlines()]
    channels = {}
    for record in records:
        if record.get("read_error"):
            continue
        channels.setdefault(record["channel"], []).append(record)

    result = {
        "format": "m1n1-t8140-g17p-live-outer-analysis-v1",
        "trace": str(trace),
        "record_count": len(records),
        "channels": {},
        "first_multi_queue_record": {},
    }
    for channel, channel_records in sorted(channels.items()):
        queue_addrs = {
            queue["queue_addr"]
            for record in channel_records
            for queue in record.get("queues", [])
            if not queue.get("read_error")
        }
        result["channels"][channel] = {
            "record_count": len(channel_records),
            "queue_subrecord_count": sum(
                len(record.get("queues", [])) for record in channel_records
            ),
            "distinct_queue_count": len(queue_addrs),
            "first_record": summarize_record(channel_records[0]),
        }
        multi = next(
            (record for record in channel_records if len(record.get("queues", [])) > 1),
            None,
        )
        if multi is not None:
            result["first_multi_queue_record"][channel] = summarize_record(multi)

    output = args.output or trace / "outer_submission_analysis.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Live outer analysis: %s" % output)
    for channel, value in result["channels"].items():
        print(
            "%s records=%d queue_subrecords=%d distinct_queues=%d"
            % (
                channel,
                value["record_count"],
                value["queue_subrecord_count"],
                value["distinct_queue_count"],
            )
        )
    for channel, record in result["first_multi_queue_record"].items():
        print(
            "%s first multi-queue sequence=%d ring_index=%d"
            % (channel, record["sequence"], record["entry_index"])
        )


if __name__ == "__main__":
    main()
