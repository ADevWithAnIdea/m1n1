# SPDX-License-Identifier: MIT
"""Explicit source objects for the qualified four-engine native C/R/C model.

Only this capture adapter fixes placement. No captured page bytes are input to
the constructors; the replay reducer separately checks their full preimages.
"""
import importlib

from g17p_replay_descriptor_source import constructors


def queue_context_pages():
    submission, _, _ = constructors()
    compute = importlib.import_module("g17p_descriptor_reduction.g17p_compute")
    # kind, context-page DVA, command DVA, queue DVA, grid, event slot, points
    objects = (
        ("compute", 0xfffffc20001d8000, 0xfffffc20c0358000, 0xfffffc20c0000000,
         0, 0, ((0, 0),)),
        ("tiling", 0xfffffc2000200000, 0xfffffc20c0018000, 0xfffffc20c00000c0,
         1, 1, ((0, 1), (1, 0))),
        ("fragment", 0xfffffc2000228000, 0xfffffc20c00b0000, 0xfffffc20c0000180,
         2, 1, ((1, 1), (0, 1), (2, 0))),
        ("compute", 0xfffffc2000250000, 0xfffffc20c0359040, 0xfffffc20c0000240,
         3, 2, ((1, 1), (2, 1), (0, 1), (3, 0))),
    )
    result = {}
    for kind, address, command, queue, grid, event, points in objects:
        if kind == "compute":
            locator_delta = (command - 0xfffffc20c0358000) // 0x20
            item = bytearray(compute.build_compute_queue_context_item(
                command, queue, grid, flags_200=0x1000000000000000,
                word_330=0, word_338=2,
                word_350=0x000110038001a002 + locator_delta,
                word_358=0x000020038001a03b + locator_delta))
        else:
            item = bytearray(submission.build_queue_context_item(
                kind, command, queue, context_id=1, dependency_grid=grid))
        flags = {"compute": 8, "tiling": 12, "fragment": 24}[kind]
        item[0x20:0x130] = submission.build_queue_context_points(flags, event, points)
        result[address] = bytes(0x200) + item + bytes(0x4000 - 0x200 - len(item))
    return result
