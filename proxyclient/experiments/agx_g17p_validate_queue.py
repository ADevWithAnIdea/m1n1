#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the command queue builders against captured queue records.

The cold-boot path builds a channel table firmware acknowledges and no queue, so the ring slot's
queue pointer stays zero and there is nothing to publish into. Building a queue is what closes that,
and the record's fields are decoded, so a builder can be checked before a boot is spent on it.

A captured record carries firmware's own running state as well as the host's configuration, so this
does not require a byte-for-byte match. It requires that every field the builder claims to set comes
back with the value it was given, and it reports which bytes of the record the builder does not
account for, since an unaccounted byte is exactly where a wrong assumption would hide.
"""
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p     # noqa: E402

CAPTURE = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                       "live_submission_targeted_20260728_003032")


def captured_records():
    """The queue record each channel's capture holds, keyed by channel name."""
    records = {}
    for channel in ("TA_0", "3D_0"):
        target = CAPTURE / channel / "target.json"
        if not target.exists():
            continue
        data = json.loads(target.read_bytes())
        for queue in data.get("queues", ()):
            blob = bytes.fromhex(queue["descriptor_hex"])
            if len(blob) >= g17p.QUEUE_DESCRIPTOR_SIZE:
                records[channel] = blob[:g17p.QUEUE_DESCRIPTOR_SIZE]
            break
    return records


def main():
    failures = 0

    def check(label, condition, detail=""):
        nonlocal failures
        print("  %-52s %s" % (label, "OK" if condition else "FAIL"))
        if not condition:
            failures += 1
            if detail:
                print("      %s" % detail)

    records = captured_records()
    check("a capture holds both queue records", len(records) == 2,
          "found %s" % sorted(records))
    if len(records) != 2:
        print("\n%d checks failed" % failures)
        return 1

    for channel, captured in sorted(records.items()):
        parsed = g17p.parse_queue_record(captured)
        built = g17p.build_queue_record(
            pointers_addr=parsed["pointers_addr"],
            ring_addr=parsed["ring_addr"],
            job_list_addr=parsed["job_list_addr"],
            context_addr=parsed["context_addr"],
            uuid=parsed["uuid"],
            priority=parsed["priority"],
            prio5=parsed["prio5"],
            unk_94=parsed["unk_94"],
        )
        rebuilt = g17p.parse_queue_record(built)

        for field in ("pointers_addr", "ring_addr", "job_list_addr", "context_addr",
                      "uuid", "priority", "prio5", "unk_94", "event_id", "unk_44"):
            check("%s: %s survives a round trip" % (channel, field),
                  rebuilt[field] == parsed[field],
                  "captured %#x, rebuilt %#x" % (parsed[field], rebuilt[field]))

        check("%s: the builder emits a full record" % channel,
              len(built) == g17p.QUEUE_DESCRIPTOR_SIZE,
              "%d bytes" % len(built))

        # Where the builder and the capture disagree, and whether that is firmware state.
        differing = [index for index in range(g17p.QUEUE_DESCRIPTOR_SIZE)
                     if built[index] != captured[index]]
        runs = []
        for index in differing:
            if runs and index == runs[-1][1] + 1:
                runs[-1][1] = index
            else:
                runs.append([index, index])
        print("      %s: %d bytes differ from the capture, in %d runs: %s"
              % (channel, len(differing), len(runs),
                 ", ".join("+%#x..%#x" % (lo, hi) for lo, hi in runs[:8])))

    # An empty pointer block and an empty job list are what a fresh queue needs.
    block = g17p.build_queue_pointers()
    indices = g17p.parse_queue_pointers(block)
    check("a fresh pointer block has every index at zero",
          all(indices[name] == 0 for name in ("done", "read", "write")
              if name in indices),
          str(indices))
    check("a fresh pointer block is the decoded size",
          len(block) == g17p.QUEUE_PTR_BLOCK_SIZE, "%d bytes" % len(block))

    job_list = g17p.build_job_list(0xfffffc20c0001000)
    check("an empty job list points at itself",
          struct.unpack_from("<Q", job_list, 8)[0] == 0xfffffc20c0001000)
    check("an empty job list is three quadwords", len(job_list) == 0x18)

    print()
    if failures:
        print("%d checks failed" % failures)
        return 1
    print("G17P queue builder gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
