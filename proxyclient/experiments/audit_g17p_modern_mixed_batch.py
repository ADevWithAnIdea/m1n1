#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently audit saved, explicitly owned C/O/C/P outputs; no GPU access.

This imports no workload builder or shim. It reconstructs the scalar/image
oracles and checks every saved physical witness, including zero guard bytes.
"""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    path = Path(directory)
    report = json.loads((path / "mixed_batch.json").read_text())
    boot = json.loads((path / "boot.json").read_text())
    assert boot["capture_read_audit"] == boot["capture_write_audit"] == []
    assert report["passed"] and report["pressure"] and not report["compute_only"]
    x = report["viewport_x"]
    assert x in (66, 68)
    assert not report["reload_clear"] or x == 66
    contributions = 33255 if report["reload_clear"] else 131072
    page, surface = 0x4000, 0x10000
    initial = [(path / ("mixed_batch_%02d_before.bin" % i)).read_bytes() for i in range(22)]
    assert all(body == bytes(len(body)) for i, body in enumerate(initial) if i != 10)
    assert len(initial[10]) == page and struct.unpack_from("<f", initial[10], 0x910) == (64,)
    expected = [None] * 22
    pixels = (0x7efc + int(x - 64) * 4, 0x7f00 + int(x - 64) * 4)
    for first, count in ((0, 1), (12, contributions)):
        for color in range(8):
            body = bytearray(surface)
            for pixel in pixels:
                struct.pack_into("<f", body, pixel, count * (color + 1) / 8)
            expected[first + color] = bytes(body)
    expected[8] = expected[20] = struct.pack("<f", .25) * 16384
    expected[9] = expected[21] = bytes([0x5a]) * 16384 + bytes(49152)
    viewport = bytearray(initial[10])
    struct.pack_into("<f", viewport, 0x910, x)
    expected[10] = bytes(viewport)
    lanes = [.5] * 64
    for pixel in pixels:
        lanes[(pixel - 0x7f00) // 4] += .125
    expected[11] = struct.pack("<64f", *lanes) + bytes(page - 256)
    assert len(report["outputs"]) == 22 and len(report["timestamps"]) == 4
    spans = []
    for i, (row, wanted) in enumerate(zip(report["outputs"], expected)):
        assert row["index"] == i and row["size"] == len(wanted) == len(initial[i])
        assert (path / ("mixed_batch_%02d.bin" % i)).read_bytes() == wanted
        assert row["exact"] and row["copyback_exact"] and row["changed"]
        if "mapped" in row:
            assert row["mapped"] == {"compute": True, "render": True}
        spans.append((row["pa"], row["pa"] + len(wanted)))
    timestamps, values = [], []
    for i, row in enumerate(report["timestamps"]):
        body = (path / ("mixed_batch_ts_%d.bin" % i)).read_bytes()
        count = 4 if i in (1, 3) else 2
        stamps = struct.unpack_from("<%dQ" % count, body)
        assert len(body) == page and body[count * 8:] == bytes(page - count * 8)
        assert all(0 < stamps[j] < stamps[j + 1] for j in range(0, count, 2))
        assert list(stamps) == row["values"] and row["valid"] and row["copyback_exact"]
        assert row.get("owned", True)
        timestamps.append(body)
        values.append(stamps)
        spans.append((row["pa"], row["pa"] + page))
    assert all(max(a) <= min(b) for a, b in zip(values, values[1:]))
    spans.sort()
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))
    writes = ({10}, set(range(10)), {11}, set(range(12, 22)))
    full = report.get("command_observations", True)
    steps = [(i, phase) for i in range(4) for phase in ("before", "after")] if full else [(0, "before")]
    assert [(row["command"], row["phase"]) for row in report["observations"]] == steps
    have_timestamps = ["timestamps" in row for row in report["observations"]]
    assert all(have_timestamps) or not any(have_timestamps)
    output_checks = timestamp_checks = 0
    for i, phase in steps:
        completed = i + (phase == "after")
        written = set().union(*writes[:completed])
        for output in range(22):
            wanted = expected[output] if output in written else initial[output]
            assert (path / ("mixed_step_%d_%s_%02d.bin" % (i, phase, output))).read_bytes() == wanted
            output_checks += 1
        for stamp in range(4):
            file = path / ("mixed_step_%d_%s_ts_%d.bin" % (i, phase, stamp))
            # The first two positive revisions recorded target witnesses but
            # not intermediate timestamp pages. Do not invent that evidence.
            if all(have_timestamps):
                assert file.read_bytes() == (timestamps[stamp] if stamp < completed else bytes(page))
                timestamp_checks += 1
    fence = report["fence"]
    assert fence["signaled"] and fence["error"] is None and len(fence["commands"]) == 4
    assert report["sync_ok"] and report["independent"]
    return dict(artifact=str(path), passed=True, viewport_x=x,
                partial_contributions=contributions, full_outputs=22, timestamp_pages=4,
                disjoint_physical_ranges=26, intermediate_output_checks=output_checks,
                intermediate_timestamp_checks=timestamp_checks,
                inter_command_probes=full, captured_reads=0, captured_writes=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+")
    args = parser.parse_args()
    print(json.dumps([audit(path) for path in args.artifacts], indent=2))
