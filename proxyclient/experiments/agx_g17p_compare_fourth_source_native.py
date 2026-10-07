#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare a source command-four pre-kick snapshot with untouched native state."""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE = 0x4000
DEFAULT_NATIVE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260813_052428/CL_2"
)


def _integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


class PageImage:
    def __init__(self, manifest_path, binary_path):
        manifest = json.loads(pathlib.Path(manifest_path).read_text())
        raw = pathlib.Path(binary_path).read_bytes()
        self.pages = {}
        self.objects = {
            record["name"]: record for record in manifest.get("objects", [])
        }
        for record in manifest["pages"]:
            address = _integer(record["dva"])
            offset = _integer(record["capture_offset"])
            body = raw[offset:offset + PAGE]
            if len(body) != PAGE:
                raise RuntimeError("short captured page at %#x" % address)
            self.pages[address] = body

    def read(self, address, size):
        address = _integer(address)
        remaining = _integer(size)
        out = bytearray()
        while remaining:
            page = address & ~(PAGE - 1)
            offset = address - page
            take = min(remaining, PAGE - offset)
            body = self.pages.get(page)
            if body is None:
                return None
            out.extend(body[offset:offset + take])
            address += take
            remaining -= take
        return bytes(out)


class SourceImage:
    def __init__(self, manifest_path):
        self.path = pathlib.Path(manifest_path)
        self.manifest = json.loads(self.path.read_text())
        raw = (self.path.parent / self.manifest["binary"]).read_bytes()
        self.objects = {}
        for record in self.manifest["objects"]:
            offset = _integer(record["capture_offset"])
            size = _integer(record["size"])
            body = raw[offset:offset + size]
            if len(body) != size:
                raise RuntimeError("short source object %s" % record["name"])
            self.objects[record["name"]] = (record, body)


def _difference_runs(left, right, limit=64):
    runs = []
    offset = 0
    while offset < min(len(left), len(right)):
        if left[offset] == right[offset]:
            offset += 1
            continue
        end = offset + 1
        while end < min(len(left), len(right)) and left[end] != right[end]:
            end += 1
        if len(runs) < limit:
            runs.append({
                "start": offset,
                "end": end,
                "source_hex": left[offset:end].hex(),
                "native_hex": right[offset:end].hex(),
            })
        offset = end
    return runs


def _qword_deltas(left, right, limit=128):
    deltas = []
    for offset in range(0, min(len(left), len(right)) - 7, 8):
        source = struct.unpack_from("<Q", left, offset)[0]
        native = struct.unpack_from("<Q", right, offset)[0]
        if source != native and len(deltas) < limit:
            deltas.append({
                "offset": offset,
                "source": source,
                "native": native,
            })
    return deltas


def _compare(name, source, native, source_dva, native_dva):
    if native is None:
        return {
            "name": name,
            "source_dva": source_dva,
            "native_dva": native_dva,
            "native_missing": True,
        }
    differing = sum(left != right for left, right in zip(source, native))
    differing += abs(len(source) - len(native))
    return {
        "name": name,
        "source_dva": source_dva,
        "native_dva": native_dva,
        "source_size": len(source),
        "native_size": len(native),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "native_sha256": hashlib.sha256(native).hexdigest(),
        "byte_exact": source == native,
        "differing_bytes": differing,
        "difference_runs": _difference_runs(source, native),
        "qword_deltas": _qword_deltas(source, native),
    }


def _control_suffix(native_target, source):
    native = native_target["device_control"]["entries"][-5:]
    record, body = source.objects["device_control_ring"]
    entries = [
        body[offset:offset + 0x40]
        for offset in range(0, len(body), 0x40)
    ]
    return {
        "native": [{
            "absolute_index": entry["absolute_index"],
            "opcode": entry["u32"][0],
            "control_class": entry["u32"][1],
            "sequence": entry["u32"][3],
            "context_word": entry["u32"][12],
            "hex": entry["hex"],
        } for entry in native],
        "source": [{
            "absolute_index": len(entries) - min(5, len(entries)) + index,
            "opcode": struct.unpack_from("<I", entry, 0)[0],
            "control_class": struct.unpack_from("<I", entry, 4)[0],
            "sequence": struct.unpack_from("<I", entry, 0x0c)[0],
            "context_word": struct.unpack_from("<I", entry, 0x30)[0],
            "hex": entry.hex(),
        } for index, entry in enumerate(entries[-5:])],
        "source_counters": source.manifest["control_counters"],
        "source_secondary_counters": source.manifest[
            "secondary_control_counters"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("--native", type=pathlib.Path, default=DEFAULT_NATIVE)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)

    source = SourceImage(args.source)
    native_firmware = PageImage(
        args.native / "pages.json", args.native / "pages.bin")
    native_client = PageImage(
        args.native / "native_client_pages.json",
        args.native / "native_client_pages.bin",
    )
    native_target = json.loads((args.native / "target.json").read_text())

    client_roles = {
        "resource": "resource_table",
        "cdm": "cdm_stream",
        "shader": "shader",
        "input_a": "input_a",
        "input_b": "input_b",
        "output": "output",
    }
    comparisons = []
    for name, (record, body) in source.objects.items():
        if name == "device_control_ring":
            continue
        if record["address_space"] == "firmware":
            native_dva = _integer(record["dva"])
            native = native_firmware.read(native_dva, len(body))
        else:
            native_name = client_roles[name]
            native_object = native_client.objects[native_name]
            native_dva = _integer(native_object["dva"])
            native = native_client.read(native_dva, len(body))
        comparisons.append(_compare(
            name, body, native, _integer(record["dva"]), native_dva))

    report = {
        "format": "m1n1-t8140-g17p-source-native-command4-diff-v1",
        "source": str(args.source),
        "native": str(args.native),
        "control_suffix": _control_suffix(native_target, source),
        "objects": comparisons,
    }
    output = args.output or args.source.with_name(
        "source_command4_native_diff.json")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for record in comparisons:
        if record.get("native_missing"):
            result = "native missing"
        elif record["byte_exact"]:
            result = "exact"
        else:
            result = "%d bytes differ" % record["differing_bytes"]
        print("%-24s %s" % (record["name"], result))
    print("report: %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
