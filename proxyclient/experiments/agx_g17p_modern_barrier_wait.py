#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only shim: admit consumers before publishing their real producer.

This fixture delays only owned producer heads/kicks. It does not synthesize
GPU output, change waits, patch completion stamps, or copy back intermediate
resources. The ordinary mixed caller still verifies every final GEM and fence.
"""
import argparse
import json
import os
from pathlib import Path
import time

import agx_g17p_modern_mixed_batch as batch


def install_probe(kind, caller, before, expected, timestamps, *, opening_value=1,
                  reuse_compute_queue=False):
    if kind not in ("compute", "tiling", "render"):
        raise ValueError("unknown delayed producer")
    adapter = caller.driver.adapter
    original_wave = adapter._submit_dependency_wave
    record = dict(kind=kind, opening_value=opening_value, source_only=True, synthetic_signal=False,
                  reuse_compute_queue=reuse_compute_queue,
                  admitted=False, blocked=False, released=False)

    def wave(*args, **kwargs):
        backend = caller.front.g17p
        directory = Path(caller.front.g17p_boot_artifact).parent
        release = backend.release_dependency_window
        publish = backend.publish_outer_with_work
        held = []
        ready = set() if kind == "compute" else {batch.partial.VIEWPORT}

        def save():
            (directory / "mixed_barrier_wait.json").write_text(
                json.dumps(record, indent=2) + "\n")

        def initial(opening, registration, render, opening_channel,
                    render_channel, notify_render=True):
            if not notify_render:
                raise ValueError("consumer-first probe cannot use diagnostic boundary snapshots")
            # The driver retains native fragment-first publication order.
            # Normalize these two withheld head writes by channel identity
            # so this fixture's mask has explicit CL/TA/fragment semantics.
            by_address = {int(address): (address, body) for address, body in render}
            render = tuple(by_address[int(backend.channels.entries[index]["state_addrs"][2])]
                           for index in (6, 7))
            mask = {"compute": 6, "tiling": 5, "render": 1}[kind]
            held.extend([(opening, opening_channel)] if kind == "compute" else
                        [(render[0], render_channel)] if kind == "tiling" else
                        [(entry, render_channel) for entry in render])
            record["producer_mask"] = mask
            record["held_heads"] = [dict(dva=address, hex=body.hex())
                                    for (address, body), _channel in held]
            save()
            return release(opening, registration, render, opening_channel,
                           render_channel, notify_render, producer_mask=mask)

        def observe_blocked():
            # Demand the firmware has read the published consumer, not just
            # that a doorbell was sent. All downstream output ranges must
            # still be exactly their complete before-images.
            heads = {"compute": (1, 1, 0), "tiling": (0, 1, 2),
                     "render": (0, 0, 2)}[kind]
            deadline = time.monotonic() + 0.5
            while True:
                if backend.event_pump is not None:
                    backend.event_pump()
                counters = [backend.channels.counters(backend.channels.entries[index])
                            for index in (6, 7, 8)]
                record["counters"] = counters
                if all(int(state[1]) == head for state, head in zip(counters, heads)):
                    break
                if time.monotonic() >= deadline:
                    save()
                    raise TimeoutError("source consumer not admitted before producer release")
            record["admitted"] = True
            rows = []
            for index, (address, initial_body) in enumerate(before.items()):
                binding = caller.bindings[address]
                body = backend.space.read(binding.bo.token["pa"], binding.size)
                (directory / ("mixed_barrier_wait_before_%02d.bin" % index)).write_bytes(body)
                desired = expected[address] if address in ready else initial_body
                rows.append(dict(dva=address, size=len(body), exact=body == desired,
                                 ready=address in ready,
                                 cpu_unchanged=bytes(binding.bo.token["map"]) == initial_body))
            stamps = []
            for index, (_object, bo) in enumerate(timestamps):
                body = backend.space.read(bo.token["pa"], batch.PAGE)
                (directory / ("mixed_barrier_wait_ts_%d.bin" % index)).write_bytes(body)
                # Only the opening compute may have run. In the tiling
                # control neither TA nor fragment should have executed yet.
                valid = (batch.timestamp_values(body, index)[1]
                         if kind != "compute" and index == 0 else not any(body))
                stamps.append(dict(index=index, valid=valid,
                                   cpu_unchanged=not any(bytes(bo.token["map"]))))
            record.update(outputs=rows, timestamps=stamps)
            save()
            if not all(row["exact"] and row["cpu_unchanged"] for row in rows):
                raise RuntimeError("source consumer output changed before producer release")
            if not all(row["valid"] and row["cpu_unchanged"] for row in stamps):
                raise RuntimeError("source consumer timestamp advanced before producer release")
            record["blocked"] = True
            save()

        def release_held():
            for (address, body), _channel in held:
                backend._write_dva(address, body)
                backend._clean_dva_range(address, len(body))
            backend.space.flush()
            backend.u.inst("dsb sy")
            for channel in dict.fromkeys(channel for _entry, channel in held):
                backend.submitter.notify(channel)
            record["released"] = True
            save()
            print("SOURCE BARRIER WAIT: %s consumers blocked; real producer released" % kind,
                  flush=True)

        def closing(producer, channel):
            if kind == "compute":
                # The two computes share one outer ring. Do not advance to
                # closing slot 2 before proving opening slot 1 is hidden.
                observe_blocked()
                release_held()
                return publish(producer, channel)
            result = publish(producer, channel)
            observe_blocked()
            release_held()
            return result

        backend.release_dependency_window = initial
        backend.publish_outer_with_work = closing
        try:
            result = original_wave(*args, opening_completion_value=opening_value,
                                   reuse_compute_queue=reuse_compute_queue, **kwargs)
            record["wave_returned"] = True
            save()
            return result
        finally:
            backend.release_dependency_window = release
            backend.publish_outer_with_work = publish

    adapter._submit_dependency_wave = wave


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("producer", choices=("compute", "tiling", "render"))
    parser.add_argument("--opening-value", type=int, default=1)
    parser.add_argument("--reuse-compute-queue", action="store_true")
    args = parser.parse_args()
    os.environ["G17P_MODERN_NATIVE_BARRIERS"] = "1"
    if os.environ.get("G17P_DEPENDENCY_SNAPSHOT"):
        parser.error("disable dependency snapshots for this test")
    return batch.run(pressure=False, command_observations=False,
        publication_probe=lambda *arguments: install_probe(
            args.producer, *arguments, opening_value=args.opening_value,
            reuse_compute_queue=args.reuse_compute_queue))


if __name__ == "__main__":
    raise SystemExit(main())
