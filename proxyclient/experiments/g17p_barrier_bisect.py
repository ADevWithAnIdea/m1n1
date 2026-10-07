# SPDX-License-Identifier: MIT
"""Audited, non-destructive reductions of the qualified dependent capture."""
import argparse
import hashlib
import json
import struct
import time
from pathlib import Path

PAGE = 0x4000
FORMAT = "g17p-dependent-capture-zero-pages-v1"
# Named host descriptor data, not shader code. These fields are independently
# source-built by build_compute_descriptor. Allow narrow field edits here,
# never whole-page zeroing or arbitrary writes through the client alias.
DESCRIPTOR_FIELD_RANGES = tuple((base + 0xf40, base + 0xf58)
                               for base in (0xfffffc20c0358000, 0xfffffc20c0359040))


def descriptor_field_pages(manifest):
    allowed = {start & ~(PAGE - 1) for start, _end in DESCRIPTOR_FIELD_RANGES}
    pages = {}
    for root in manifest["root_mappings"]:
        if int(root["root_ctx_id"]) != 64:
            continue
        for row in root["mappings"]:
            address = int(row["va"])
            if address in allowed and row.get("blob_index") is not None:
                if address in pages and pages[address] != int(row["blob_index"]):
                    raise ValueError("ambiguous descriptor field mapping")
                pages[address] = int(row["blob_index"])
    return pages


def delayed_producer_control(kind, channels, read_word, write_word, kick,
                             read_output, pump, directory):
    """Admit a consumer first, then publish real work; never patch a signal."""
    from agx_g17p_replay_native_barriers import EXPECTED, HELD_KICKS, validate_outputs
    profiles = {
        "compute": ({"TA_2": 1, "3D_2": 1, "CL_2": 0}, (), (8,)),
        "tiling": ({"TA_2": 0, "3D_2": 1, "CL_2": 1}, ("positions",), (10, 8)),
        "render": ({"TA_2": 0, "3D_2": 0, "CL_2": 2}, ("positions",), (10,)),
    }
    if kind not in profiles:
        raise ValueError("unknown delayed native producer")
    heads, ready, messages = profiles[kind]
    by_name = {channel["name"]: channel for channel in channels}
    if (set(by_name) != set(heads) or
            any(int(by_name[name]["captured_producer"]) != count
                for name, count in (("TA_2", 1), ("3D_2", 1), ("CL_2", 2)))):
        raise ValueError("delayed publication requires the qualified four-queue graph")
    path = directory / "barrier_delayed_producer.json"
    report = dict(kind=kind, initial_heads=heads, ready=ready,
                  synthetic_signal=False, released=False, passed_before_release=False)

    def save():
        path.write_text(json.dumps(report, indent=2) + "\n")

    for name, channel in by_name.items():
        if read_word(channel["state_addrs"][2]) != 0:
            raise ValueError("delayed publication must start with hidden producers")
    for name, value in heads.items():
        write_word(by_name[name]["state_addrs"][2], value)
    for channel in messages:
        kick(0x83000000000000 | channel)
    deadline = time.monotonic() + 0.5
    while True:
        pump()
        counters = {name: [read_word(address) for address in channel["state_addrs"][:3]]
                    for name, channel in by_name.items()}
        body = read_output()
        admitted = all(counters[name][1] == head for name, head in heads.items())
        ready_exact = all(body[EXPECTED[name][0]:EXPECTED[name][0] + len(EXPECTED[name][1])]
                          == EXPECTED[name][1] for name in ready)
        if admitted and ready_exact:
            break
        if time.monotonic() >= deadline:
            report.update(counters=counters, admitted=admitted, ready_exact=ready_exact)
            (directory / "barrier_delayed_before.bin").write_bytes(body)
            save()
            raise TimeoutError("consumer admission/predecessor output not observed")
    (directory / "barrier_delayed_before.bin").write_bytes(body)
    report.update(counters=counters, admitted=admitted, ready_exact=ready_exact,
                  before=validate_outputs(bytes(PAGE), body))
    save()
    for name in set(EXPECTED) - set(ready):
        offset, expected = EXPECTED[name]
        if body[offset:offset + len(expected)] != bytes(len(expected)):
            raise RuntimeError("consumer %s executed before its producer publication" % name)
    report["passed_before_release"] = True
    save()
    # Real producer commands and original wait fields remain untouched. Only
    # advance their native outer heads and send the native work notifications.
    for name, channel in by_name.items():
        write_word(channel["state_addrs"][2], channel["captured_producer"])
    for message in HELD_KICKS:
        kick(message)
    report["released"] = True
    save()
    print("BARRIER DELAYED PRODUCER: %s consumer admitted and blocked; real producer released" %
          kind, flush=True)
    return report


def release_control(probe, read_output, read_word, write_word, pump, directory):
    """Diagnostic only: observe a blocked consumer, then synthesize its signal."""
    from agx_g17p_replay_native_barriers import EXPECTED, validate_outputs
    ready, blocked = probe["ready"], probe["blocked"]
    if (not ready or not blocked or set(ready) & set(blocked) or
            set(ready + blocked) != set(EXPECTED)):
        raise ValueError("release probe must partition all three output witnesses")
    deadline = time.monotonic() + 0.5
    while True:
        pump()
        body = read_output()
        if all(body[EXPECTED[name][0]:EXPECTED[name][0] + len(EXPECTED[name][1])]
               == EXPECTED[name][1] for name in ready):
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("release probe predecessor did not execute")
    before = validate_outputs(bytes(PAGE), body)
    (directory / "barrier_release_before.bin").write_bytes(body)
    report = dict(probe=probe, before=before, synthetic_signal=True, released=False)
    path = directory / "barrier_release.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in blocked:
        offset, expected = EXPECTED[name]
        if body[offset:offset + len(expected)] != bytes(len(expected)):
            raise RuntimeError("unsatisfied consumer %s changed before diagnostic release" % name)
    address = int(probe["dva"])
    actual = read_word(address)
    report["observed_word"] = actual
    path.write_text(json.dumps(report, indent=2) + "\n")
    if actual != int(probe["expected"]):
        raise RuntimeError("release signal preimage %#x != %#x" % (actual, int(probe["expected"])))
    write_word(address, int(probe["value"]))
    report["released"] = True
    path.write_text(json.dumps(report, indent=2) + "\n")
    print("BARRIER RELEASE: predecessor exact, consumers zero; signal %#x: %#x -> %#x; no kick" %
          (address, actual, int(probe["value"])), flush=True)


def ownership_candidates(manifest, ram):
    """Keep startup, transport, descriptors and caller programs unchanged."""
    aliases = {}
    for root in manifest["root_mappings"]:
        for row in root["mappings"]:
            if row.get("blob_index") is not None:
                aliases.setdefault(int(row["blob_index"]), []).append(
                    (int(root["root_ctx_id"]), int(row["va"])))
    result = []
    for blob, names in aliases.items():
        # A client alias may contain caller resources/programs. Exclude it
        # even when another mapping makes the same PA firmware-accessible.
        if any(context == 1 for context, _ in names):
            continue
        firmware = [address for context, address in names if context == 64]
        if len(firmware) != 1:
            continue
        dva = firmware[0]
        if not (0xfffffc20015d8000 <= dva < 0xfffffc2001660000 or
                0xfffffc20c0820000 <= dva < 0xfffffc20c0884000 or
                0xfffffc20001d8000 <= dva < 0xfffffc2000280000):
            continue
        body = ram[blob * PAGE:(blob + 1) * PAGE]
        if not any(body):
            continue
        result.append(dict(blob_index=blob, dva=dva, aliases=names,
                           nonzero_bytes=sum(bool(value) for value in body)))
    return sorted(result, key=lambda row: row["dva"])


def zero_page_overrides(manifest, ram, plan):
    if plan.get("format") != FORMAT or plan.get("ram_sha256") != manifest["ram_sha256"]:
        raise ValueError("reduction must identify this exact captured RAM image")
    candidates = {row["blob_index"]: row for row in ownership_candidates(manifest, ram)}
    selected = plan.get("zero_blob_indices", [])
    if len(set(selected)) != len(selected) or any(type(index) is not int for index in selected):
        raise ValueError("reduction page indices must be unique integers")
    if set(selected) - candidates.keys():
        raise ValueError("reduction names a protected or non-candidate page")
    pages = {int(row["index"]): row for row in manifest["blob_pages"]}
    overrides, report = {}, []
    for index in sorted(selected):
        row = pages[index]
        original = ram[index * PAGE:(index + 1) * PAGE]
        if len(original) != PAGE or hashlib.sha256(original).hexdigest() != row["sha256"]:
            raise ValueError("candidate page checksum mismatch")
        pa = int(row["original_pa"])
        overrides[pa] = bytes(PAGE)
        report.append(dict(candidates[index], pa=pa, original_sha256=row["sha256"]))
    writes = []
    by_dva = {row["dva"]: index for index, row in candidates.items()}
    source_objects = []
    if plan.get("source_queue_contexts"):
        from g17p_replay_barrier_source import queue_context_pages
        for address, body in queue_context_pages().items():
            index = by_dva[address]
            if index in selected:
                raise ValueError("source context also selected for whole-page zeroing")
            original = ram[index * PAGE:(index + 1) * PAGE]
            if body != original:
                raise ValueError("source context differs from qualified native model at %#x" % address)
            pa = int(pages[index]["original_pa"])
            overrides[pa] = body
            source_objects.append(dict(dva=address, pa=pa, size=len(body),
                                       sha256=hashlib.sha256(body).hexdigest()))
    covered = set()
    descriptor_pages = descriptor_field_pages(manifest)
    for write in plan.get("writes", []):
        address = int(write["dva"])
        page = address & ~(PAGE - 1)
        index = by_dva.get(page)
        offset = address - page
        body, expected = bytes.fromhex(write["hex"]), bytes.fromhex(write["expected_hex"])
        if index is None and any(start <= address and address + len(body) <= end
                                 for start, end in DESCRIPTOR_FIELD_RANGES):
            index = descriptor_pages.get(page)
        if (index is None or index in selected or not body or
                len(body) != len(expected) or offset + len(body) > PAGE):
            raise ValueError("field reduction crosses a protected/zeroed page or has invalid size")
        locations = set(range(address, address + len(body)))
        if covered & locations:
            raise ValueError("overlapping field reductions")
        covered.update(locations)
        original = ram[index * PAGE:(index + 1) * PAGE]
        row = pages[index]
        if (len(original) != PAGE or hashlib.sha256(original).hexdigest() != row["sha256"] or
                original[offset:offset + len(body)] != expected):
            raise ValueError("field reduction preimage mismatch")
        pa = int(row["original_pa"])
        patched = bytearray(overrides.get(pa, original))
        patched[offset:offset + len(body)] = body
        overrides[pa] = bytes(patched)
        writes.append(dict(write, pa=pa + offset, blob_index=index))
    return overrides, dict(format=FORMAT, ram_sha256=manifest["ram_sha256"],
                           zeroed_pages=report, zeroed_bytes=len(report) * PAGE,
                           writes=writes, source_queue_contexts=source_objects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--select", default="all", help="candidate indices, comma separated; or all/none")
    parser.add_argument("--write-u32", action="append", default=[], metavar="DVA=VALUE")
    parser.add_argument("--queue-points", action="append", default=[],
                        metavar="HEADER_DVA=QUEUE:VALUE,...",
                        help="source-build one context point list, retaining its header tag/flags")
    parser.add_argument("--source-contexts", action="store_true")
    parser.add_argument("--release-u32", metavar="DVA=EXPECTED:VALUE")
    parser.add_argument("--release-ready", default="positions")
    parser.add_argument("--release-blocked", default="texture,result")
    parser.add_argument("--delay-producer", choices=("compute", "tiling", "render"))
    args = parser.parse_args()
    manifest = json.loads((args.snapshot / "manifest.json").read_text())
    ram = (args.snapshot / manifest["ram_file"]).read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise ValueError("snapshot RAM checksum mismatch")
    candidates = ownership_candidates(manifest, ram)
    selected = (range(len(candidates)) if args.select == "all" else
                [] if args.select == "none" else
                [int(value) for value in args.select.split(",")])
    plan = dict(format=FORMAT, ram_sha256=manifest["ram_sha256"],
                snapshot=str(args.snapshot.resolve()), candidates=candidates,
                zero_blob_indices=[candidates[index]["blob_index"] for index in selected])
    by_dva = {row["dva"]: row["blob_index"] for row in candidates}
    by_dva.update(descriptor_field_pages(manifest))
    plan["writes"] = []
    plan["source_queue_contexts"] = args.source_contexts
    if args.delay_producer:
        if args.release_u32:
            parser.error("real producer delay cannot be combined with synthetic release")
        plan["delay_producer"] = args.delay_producer
    if args.release_u32:
        address, values = args.release_u32.split("=")
        expected, value = (int(part, 0) for part in values.split(":"))
        plan["release_probe"] = dict(dva=int(address, 0), expected=expected, value=value,
                                     ready=args.release_ready.split(","),
                                     blocked=args.release_blocked.split(","))
    for value in args.write_u32:
        address, scalar = (int(part, 0) for part in value.split("="))
        index = by_dva[address & ~(PAGE - 1)]
        offset = index * PAGE + (address & (PAGE - 1))
        plan["writes"].append(dict(dva=address, hex=struct.pack("<I", scalar).hex(),
                                   expected_hex=ram[offset:offset + 4].hex()))
    for value in args.queue_points:
        from g17p_replay_descriptor_source import constructors
        submission, _render, _compute = constructors()
        address, entries = value.split("=")
        address = int(address, 0)
        if address not in (0xfffffc20001d8220, 0xfffffc2000200220,
                           0xfffffc2000228220, 0xfffffc2000250220):
            raise ValueError("point-list edits require a qualified queue-context header")
        index = by_dva[address & ~(PAGE - 1)]
        offset = index * PAGE + (address & (PAGE - 1))
        header, = struct.unpack_from("<Q", ram, offset)
        points = tuple(tuple(int(part, 0) for part in entry.split(":"))
                       for entry in entries.split(","))
        body = submission.build_queue_context_points((header >> 40) & 0xff,
                                                     (header >> 32) & 0xff, points)
        plan["writes"].append(dict(dva=address, hex=body.hex(),
                                   expected_hex=ram[offset:offset + len(body)].hex()))
    zero_page_overrides(manifest, ram, plan)
    with args.plan.open("x") as output:
        json.dump(plan, output, indent=2)
        output.write("\n")
    for index, row in enumerate(candidates):
        print(index, hex(row["dva"]), row["blob_index"], row["nonzero_bytes"])
    print("Reduction plan:", args.plan, "selected", len(plan["zero_blob_indices"]))


if __name__ == "__main__":
    main()
