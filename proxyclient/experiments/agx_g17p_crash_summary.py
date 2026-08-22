#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize generated ASC crash state without reading or disassembling firmware."""

import argparse
import json
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.fw.asc.crash import CrashLog  # noqa: E402


def summarize(data):
    crash = CrashLog.parse(data)
    result = {
        "format": "m1n1-asc-crash-summary-v1",
        "header": {
            "version": int(crash.header.ver),
            "total_size": int(crash.header.total_size),
            "flags": int(crash.header.flags),
        },
        "entries": [],
    }

    for entry in crash.entries:
        record = {"type": entry.type, "flags": int(entry.flags)}
        payload = entry.payload
        if entry.type == "Crg8":
            record.update({
                "pc": int(payload.pc),
                "sp": int(payload.sp),
                "psr": int(payload.psr),
                "far": int(payload.far),
                "esr": int(payload.esr),
                "registers": [int(value) for value in payload.regs],
            })
        elif entry.type == "CasC":
            record.update({
                name: int(getattr(payload, name))
                for name in (
                    "l2c_err_sts", "l2c_err_adr", "l2c_err_inf",
                    "lsu_err_sts", "fed_err_sts", "mmu_err_sts",
                )
            })
        elif entry.type == "Ccst":
            record["task"] = int(payload.task)
            record["stack"] = [
                int(value) for value in payload.stack if int(value)
            ]
        elif entry.type == "Cstr":
            record["id"] = int(payload.id)
            record["message"] = payload.string
        elif entry.type == "Cmbx":
            record["mailbox_type"] = int(payload.type)
            record["index"] = int(payload.index)
            record["messages"] = [{
                "endpoint": int(message.endpoint),
                "message": int(message.message),
                "timestamp": int(message.timestamp),
            } for message in payload.messages]
        elif entry.type == "Ccdp":
            record["mappings"] = [{
                "va": int(mapping.va),
                "pa": int(mapping.pa),
                "flags": int(mapping.unk_10),
            } for mapping in payload.entries]
        result["entries"].append(record)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("crash", type=pathlib.Path)
    parser.add_argument("-o", "--output", type=pathlib.Path)
    args = parser.parse_args()

    report = summarize(args.crash.read_bytes())
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
