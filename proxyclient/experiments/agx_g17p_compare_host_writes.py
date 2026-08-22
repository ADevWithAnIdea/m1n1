#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare final native CPU stores with a generated pre-notify graph.

The stage-2 trace contains only host CPU writes. Replaying the stores into a
byte map therefore provides an ownership filter: firmware DMA and unrelated
snapshot differences cannot appear in this comparison.
"""

import argparse
import json
import pathlib


PAGE = 0x4000


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def load_generated(path):
    pages = {}
    for page_path in path.glob("*.bin"):
        data = page_path.read_bytes()
        if len(data) != PAGE:
            raise ValueError(
                "%s is %#x bytes, expected %#x" %
                (page_path, len(data), PAGE)
            )
        pages[int(page_path.stem, 16)] = data
    if not pages:
        raise ValueError("no generated pages found in %s" % path)
    return pages


def final_host_bytes(trace, pages):
    final = {}
    missing = set()
    represented_stores = 0
    for write in sorted(trace["writes"], key=lambda item: integer(item["sequence"])):
        width = integer(write["width"])
        value = integer(write["data"]).to_bytes(width, "little")
        sequence = integer(write["sequence"])
        pc = integer(write["pc"])
        cpu = integer(write["cpu"])
        represented = False
        for base_address in write.get("dvas", ()):
            base_address = integer(base_address)
            if (base_address & ~(PAGE - 1)) not in pages:
                missing.add(base_address & ~(PAGE - 1))
                continue
            represented = True
            for offset, byte in enumerate(value):
                address = base_address + offset
                if (address & ~(PAGE - 1)) not in pages:
                    missing.add(address & ~(PAGE - 1))
                    continue
                final[address] = {
                    "value": byte,
                    "sequence": sequence,
                    "pc": pc,
                    "cpu": cpu,
                    "width": width,
                    "store_address": base_address,
                }
        represented_stores += int(represented)
    return final, missing, represented_stores


def mismatch_runs(addresses, final, pages):
    runs = []
    for address in sorted(addresses):
        if runs and address == runs[-1][-1] + 1:
            runs[-1].append(address)
        else:
            runs.append([address])

    output = []
    for run in runs:
        native = bytes(final[address]["value"] for address in run)
        generated = bytes(
            pages[address & ~(PAGE - 1)][address & (PAGE - 1)]
            for address in run
        )
        output.append({
            "start": run[0],
            "end": run[-1] + 1,
            "native": native,
            "generated": generated,
            "sequences": sorted({final[address]["sequence"] for address in run}),
            "pcs": sorted({final[address]["pc"] for address in run}),
            "cpus": sorted({final[address]["cpu"] for address in run}),
            "store_widths": sorted({final[address]["width"] for address in run}),
        })
    return output


def abbreviated(data, limit=32):
    if len(data) <= limit:
        return data.hex()
    return data[:limit].hex() + "...(%#x bytes)" % len(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=pathlib.Path)
    parser.add_argument("generated", type=pathlib.Path)
    parser.add_argument("--details", type=int, default=200,
                        help="maximum mismatch runs to print")
    args = parser.parse_args()

    trace = json.loads(args.trace.read_text())
    pages = load_generated(args.generated)
    final, missing, represented_stores = final_host_bytes(trace, pages)

    matches = []
    mismatches = []
    per_page = {}
    for address, record in sorted(final.items()):
        generated = pages[address & ~(PAGE - 1)][address & (PAGE - 1)]
        mismatch = record["value"] != generated
        (mismatches if mismatch else matches).append(address)
        row = per_page.setdefault(address & ~(PAGE - 1), [0, 0])
        row[0] += 1
        row[1] += int(mismatch)

    print("Trace: %s" % args.trace)
    print("Generated graph: %s" % args.generated)
    print("Native stores: %d total, %d represented in generated graph, %d dropped" % (
        len(trace["writes"]), represented_stores, integer(trace.get("dropped", 0))))
    print("Host-owned final bytes: %d across %d pages; %d match, %d mismatch" % (
        len(final), len(per_page), len(matches), len(mismatches)))
    print("Generated pages: %d; missing traced DVA pages: %d" %
          (len(pages), len(missing)))

    print("\npage                 touched  mismatch")
    for page, (touched, mismatch) in sorted(
            per_page.items(), key=lambda item: (item[1][1], item[1][0]),
            reverse=True):
        print("%#018x  %7d  %8d" % (page, touched, mismatch))

    runs = mismatch_runs(mismatches, final, pages)
    print("\nMismatch runs: %d" % len(runs))
    for run in runs[:args.details]:
        print("%#018x..%#018x (+%#x..+%#x) seq=%s cpu=%s width=%s" % (
            run["start"], run["end"], run["start"] & (PAGE - 1),
            run["end"] & (PAGE - 1), run["sequences"], run["cpus"],
            run["store_widths"]))
        print("  native   %s" % abbreviated(run["native"]))
        print("  generated %s" % abbreviated(run["generated"]))
        print("  pc %s" % ", ".join("%#x" % pc for pc in run["pcs"]))
    if len(runs) > args.details:
        print("... %d more mismatch runs" % (len(runs) - args.details))

    if missing:
        print("\nMissing traced DVA pages:")
        for page in sorted(missing):
            print("%#018x" % page)
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
