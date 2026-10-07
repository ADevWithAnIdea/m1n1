#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit saved caller-owned isolation witnesses without the shim or fixture."""
import argparse
import json
from pathlib import Path
import struct


def disjoint(ranges):
    spans = sorted((pa, pa + size) for pa, size in ranges)
    return all(start > 0 and start < end for start, end in spans) and all(
        a[1] <= b[0] for a, b in zip(spans, spans[1:]))


def audit(directory):
    path = Path(directory)
    report = json.loads((path / "render_isolation.json").read_text())
    boot = json.loads((path / "boot.json").read_text())
    assert report["passed"] and len(report["results"]) == 3
    assert boot["capture_read_audit"] == boot["capture_write_audit"] == []
    mixed = report["mixed"]
    usc, page, size = 0x10000000000, 0x4000, 0x10000
    colors = tuple(usc + 0x58000 + i * 0x18000 for i in range(8))
    zls = (usc + 0x8000000, usc + 0x8010000)
    viewport, compute_output = 0x100006c000, usc + 0x30074000
    prior, ranges, previous_end = [], [], 0
    for index, row in enumerate(report["results"]):
        assert row["label"] == ("A1", "B1", "A2")[index] and row["passed"]
        x = 68 if index == 1 else 66
        pixels = (0x7efc + (x - 64) * 4, 0x7f00 + (x - 64) * 4)
        expected = {}
        for shift, count in ((0, 1 if mixed else index + 1),):
            for color, address in enumerate(colors):
                body = bytearray(size)
                for pixel in pixels:
                    struct.pack_into("<f", body, pixel, count * (color + 1) / 8)
                expected[address + shift] = bytes(body)
        expected[zls[0]] = struct.pack("<f", .25) * 16384
        expected[zls[1]] = bytes([0x5a]) * 16384 + bytes(49152)
        order = list(colors + zls)
        if mixed:
            original = (path / ("isolation_%d_before_output_10.bin" % index)).read_bytes()
            assert len(original) == page and struct.unpack_from("<f", original, 0x910) == (64,)
            body = bytearray(original)
            struct.pack_into("<f", body, 0x910, x)
            expected[viewport] = bytes(body)
            lanes = [.5] * 64
            for pixel in pixels:
                lanes[(pixel - 0x7f00) // 4] += .125
            expected[compute_output] = struct.pack("<64f", *lanes) + bytes(page - 256)
            order.extend((viewport, compute_output))
            count = 33255 if report["reload_clear"] and index == 2 else 131072
            for color, address in enumerate(colors):
                body = bytearray(size)
                for pixel in pixels:
                    struct.pack_into("<f", body, pixel, count * (color + 1) / 8)
                expected[address + 0x4000000] = bytes(body)
            for address in zls:
                expected[address + 0x4000000] = expected[address]
            order.extend(address + 0x4000000 for address in colors + zls)
        assert {item["dva"] for item in row["outputs"]} == set(expected)
        for number, address in enumerate(order):
            initial = (path / ("isolation_%d_before_output_%02d.bin" % (index, number))).read_bytes()
            assert len(initial) == len(expected[address])
            if address != viewport:
                assert initial == bytes(len(initial))
        snapshots = []
        for item in row["outputs"]:
            body = (path / ("isolation_%d_%x.bin" % (index, item["dva"]))).read_bytes()
            assert body == expected[item["dva"]] and item["exact"] and item["copyback"]
            assert item["size"] == len(body)
            snapshots.append((item["pa"], body))
        assert len(row["timestamps"]) == (4 if mixed else 1)
        for number, stamp in enumerate(row["timestamps"]):
            body = (path / ("isolation_%d_ts_%d.bin" % (index, number))).read_bytes()
            before = (path / ("isolation_%d_before_ts_%d.bin" % (index, number))).read_bytes()
            assert before == bytes(page) and len(body) == page
            count = 2 if mixed and number in (0, 2) else 4
            values = struct.unpack_from("<%dQ" % count, body)
            assert body[count * 8:] == bytes(page - count * 8)
            assert list(values) == stamp["values"]
            assert all(0 < values[j] < values[j + 1] for j in range(0, count, 2))
            assert previous_end <= min(values)
            previous_end = max(values)
            assert stamp["valid"] and stamp["owned"] and stamp["copyback"]
            snapshots.append((stamp["pa"], body))
        for number, (pa, wanted) in enumerate(prior):
            for suffix in ("before_prior", "prior"):
                body = (path / ("isolation_%d_%s_%03d.bin" % (index, suffix, number))).read_bytes()
                assert body == wanted
        assert row["prior_checks"] == len(prior) and row["prior_unchanged"]
        assert row["inactive_absent"] and row["sentinel_exact"]
        if mixed:
            assert row["active_root"] and row["compute_inactive_absent"] and row["timestamp_ordered"]
        assert all(item["exact"] and item.get("compute_exact", True) for item in row["mappings"])
        assert row["sync_ok"] and row["independent"]
        assert row["fence"]["signaled"] and row["fence"]["error"] is None
        assert len(row["fence"]["commands"]) == (4 if mixed else 1)
        if index == 1:
            assert row["destroyed_and_stale_rejected"]
            live = report["results"][0]["mappings"] + row["mappings"]
            assert disjoint((item["pa"], item["size"]) for item in live)
        prior.extend(snapshots)
        ranges.extend((pa, len(body)) for pa, body in snapshots)
    assert disjoint(ranges)
    return dict(artifact=str(path), passed=True, mode="COCP" if mixed else "ordinary",
                independent_outputs=66 if mixed else 30, timestamp_pages=12 if mixed else 3,
                disjoint_output_timestamp_ranges=len(ranges),
                retained_pre_post_checks=156 if mixed else 66,
                partial_reload_control=report["reload_clear"], captured_reads=0, captured_writes=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+")
    args = parser.parse_args()
    print(json.dumps([audit(path) for path in args.artifacts], indent=2))
