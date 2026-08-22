#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Attach a backend to firmware another process started, and report what it can see.

`agx_g17p_boot.py` starts both coprocessors and exits; the proxy and the firmware it started stay
up. This connects `G17PShimBackend` to that firmware using the attach block the boot wrote into its
own artifact, and reads the state a backend needs before it can do anything: the channel table, the
work queues and their indices.

Nothing is published and no doorbell is rung. This answers whether the backend can find its way
around a live firmware, which is the step before it can submit to one.

    M1N1DEVICE=/dev/m1n1-neo PYTHONPATH="$PWD/proxyclient" \\
      .venv/bin/python3 proxyclient/experiments/agx_g17p_attach.py
"""

import argparse
import glob
import json
import os
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.setup import p, u, iface           # noqa: E402
from m1n1.agx import g17p                    # noqa: E402
from m1n1.agx import g17p_shim               # noqa: E402

ARTIFACTS = pathlib.Path(
    os.environ.get("G17P_ARTIFACTS",
                   os.path.expanduser("~/asahi_re/artifacts/agx_g17p")))


def newest_attach():
    """The attach block of the most recent boot that recorded one."""
    newest = None
    for path in sorted(ARTIFACTS.glob("boot_*/boot.json")):
        try:
            attach = json.loads(path.read_text()).get("attach")
        except (OSError, ValueError):
            continue
        if attach and attach.get("initdata_addr"):
            newest = (path, attach)
    return newest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fill-items", choices=("none", "all", "pointers", "scalars"),
                        default="none",
                        help="fill the backend's item bodies from the ones that complete, by "
                             "class of field: whole body, the high-half pointers only, or "
                             "everything that is not one of those pointers")
    parser.add_argument("--reset-render-state", action="store_true",
                        help="zero the per-render state pages before each submission after the "
                             "first. A second submission otherwise reuses status pages, the "
                             "tilemap and the parameter-buffer metadata that the first render "
                             "wrote, which a driver resets per render")
    parser.add_argument("--queue-pair", type=int, default=0, metavar="N",
                        help="submit on channel pair N. A pair whose ring slot names no queue "
                             "has one built first, which is what opening a second context "
                             "needs, and separates a per-pair work limit from a per-world one")
    parser.add_argument("--alternate-queue-pairs", action="store_true",
                        help="alternate queue pairs 0 and 1 over TA_0/3D_0, matching the native "
                             "channel-ring stream instead of treating a queue pair as a channel "
                             "pair")
    parser.add_argument("--queue-job-list", type=lambda v: int(v, 0), metavar="ADDR",
                        help="when creating a queue pair, use this existing job-list head "
                             "instead of allocating one. A native created pair uses "
                             "0xfffffc2000000000")
    parser.add_argument("--dump", action="append", default=[], metavar="ADDR:LEN",
                        help="dump LEN bytes at device address ADDR after attaching; repeatable")
    parser.add_argument("--dump-dir", type=pathlib.Path,
                        help="also save every --dump span as ADDR.bin in this directory")
    parser.add_argument("--write64", action="append", default=[], metavar="ADDR:VALUE",
                        help="write one 64-bit value at a device address after attaching; "
                             "repeatable and intended for isolated live-state probes")
    parser.add_argument("--raw-message", action="append", default=[],
                        type=lambda v: int(v, 0), metavar="VALUE",
                        help="send one exact 64-bit message to endpoint 0x21 after any writes; "
                             "repeatable")
    parser.add_argument("--keep-staged", action="store_true",
                        help="do not rewind the queue indices before submitting. The un-stage "
                             "rewrites done and read, which are firmware's, and a world where "
                             "firmware has already advanced them fetches afterwards and never "
                             "completes; a driver appends instead")
    parser.add_argument("--publish-in-place", action="store_true",
                        help="with --publish, rewrite the current item-ring group in place and "
                             "keep the queue head unchanged. Native repeated work advances only "
                             "the channel producer while reusing the same three item buffers")
    parser.add_argument("--doorbell-channels", default="0", metavar="LIST",
                        help="comma-separated channel values to ring, default \"0\". The field "
                             "encodes (queue << 2) | kind, and this path has only ever rung 0, "
                             "which names the pair's tiling queue")
    parser.add_argument("--fixed-item-index", action="store_true",
                        help="build every submission as item 0, so each names the same pool "
                             "records instead of advancing them; separates a pool the firmware "
                             "runs out of from a limit on submissions themselves")
    parser.add_argument("--drain-events", type=int, default=0, metavar="N",
                        help="pull up to N messages out of the mailbox before each submission "
                             "after the first; this path has never read firmware's outbound "
                             "messages, and a host drains its completion events")
    parser.add_argument("--advance-cursor", type=lambda v: int(v, 0), default=0, metavar="STEP",
                        help="add STEP to the shared control object's +0x48 cursor before each "
                             "submission after the first; a working host walks it 0x88, 0xb0, "
                             "0xd8 while this path leaves it at its post-opening value")
    parser.add_argument("--slot-wrap", type=int, default=0, metavar="N",
                        help="reuse channel ring slots modulo N instead of always taking the "
                             "next still-zero one; firmware stops consuming after a few slots "
                             "and this asks whether the ring is meant to be reused")
    parser.add_argument("--watch-control", action="store_true",
                        help="print the shared control object's counters and each queue's ring "
                             "counters after every submission, to see what a second group "
                             "consumes that a third then cannot get")
    parser.add_argument("--control-done-between", type=int, default=0, metavar="N",
                        help="send N control-done messages before each submission after the "
                             "first; a working host's inter-submission protocol is two of them "
                             "and a work doorbell, and this path sends only the doorbell")
    parser.add_argument("--native-control-done", action="store_true",
                        help="send the native inter-submission control-done sequence: two before "
                             "submission 2, then one before each later submission")
    parser.add_argument("--submit-count", type=int, default=1,
                        help="how many submissions to make in a row, each built fresh; the "
                             "one-group limit was measured on groups that never completed, so "
                             "this asks whether a completed group frees the allowance")
    parser.add_argument("--reuse-queue-items", action="store_true",
                        help="refresh the first three item buffers for every later generated "
                             "submission and leave the queue head at three, matching native "
                             "repeated publication")
    parser.add_argument("--diff-render-inputs", action="store_true",
                        help="snapshot the render pages before the backend builds and again "
                             "after, to name the inputs it generates differently from the boot")
    parser.add_argument("--graph-arena", metavar="ADDR", default=None,
                        help="build the submission graph at this address in firmware's own "
                             "space instead of in the submitting context; \"auto\" picks the "
                             "first free mapped run past the boot's own items")
    parser.add_argument("--arena-pages", type=int, default=64,
                        help="how many pages the arena may use (default 64)")
    parser.add_argument("--use-reference-items", action="store_true",
                        help="publish through the backend but name the boot's own item "
                             "addresses, to separate a wrong body from a wrong address")
    parser.add_argument("--submit", action="store_true",
                        help="with --build-submission, publish what the backend built rather than "
                             "only reporting it")
    parser.add_argument("--build-submission", action="store_true",
                        help="have the backend build a submission from a command buffer and the "
                             "artifact's parameters, and report what it produced, without "
                             "publishing it")
    parser.add_argument("--clear-extent", action="store_true",
                        help="destructive negative control: zero the measured accelerator-written "
                             "pages before publishing. Those pages are also render input, so this "
                             "normally suppresses execution rather than isolating its output")
    parser.add_argument("--build-items", action="store_true",
                        help="with --publish, build the group's work items in this process at the "
                             "next slot of each array rather than republishing the boot's")
    parser.add_argument("--publish", action="store_true",
                        help="un-stage the group a boot staged and publish it again from this "
                             "process, through the backend's own submitter, then ring for it")
    parser.add_argument("--ring", action="store_true",
                        help="ring the primary's work doorbell from this process, to dispatch a "
                             "group a boot staged and deliberately did not ring for")
    parser.add_argument("--initdata", type=lambda v: int(v, 0),
                        help="attach to this initdata address instead of the newest artifact's")
    args = parser.parse_args()

    if args.initdata is not None:
        initdata = args.initdata
        context = g17p_shim.SHIM_CONTEXT
        firmware_root = "high"
        # No artifact was read, so there is no extent map and no render can be verified here.
        attach = {}
        print("Attaching to initdata %#x, given on the command line" % initdata)
    else:
        found = newest_attach()
        if found is None:
            raise SystemExit("no boot artifact records an attach block")
        path, attach = found
        initdata = int(attach["initdata_addr"])
        context = int(attach.get("context", g17p_shim.SHIM_CONTEXT))
        firmware_root = "high"   # firmware's addresses resolve through the upper root
        print("Attaching to the firmware started by %s" % path)
        print("  initdata %#x, context %d" % (initdata, context))

    # A real doorbell, so the backend can complete a publication. The endpoint objects are made by
    # the ASC's start sequence, which is not run here, so it is instantiated against the live
    # mailbox directly. Constructing the ASC does not restart the coprocessor.
    from m1n1.fw.asc import StandardASC
    from m1n1.fw.asc.base import ASCBaseEndpoint
    from m1n1.agx.g17p import MSG_WORK_DOORBELL
    from m1n1.utils import Register64

    class GpuMsg(Register64):
        TYPE = 55, 48
        CHANNEL = 47, 32

    class DoorbellEndpoint(ASCBaseEndpoint):
        BASE_MESSAGE = GpuMsg
        SHORT = "db"

    _asc = StandardASC(u, int(u.adt["/arm-io/gfx-asc"].get_reg(0)[0]))
    _doorbell_ep = DoorbellEndpoint(_asc, 0x21)

    _ring_channels = [int(part, 0) for part in args.doorbell_channels.split(",") if part != ""]

    def doorbell(value=0):
        # A caller that names a channel gets that one; the default rings every channel asked for
        # on the command line, so a pair can be notified on both its queues.
        for channel in ([value] if value else _ring_channels):
            _doorbell_ep.send(GpuMsg(TYPE=MSG_WORK_DOORBELL, CHANNEL=channel))

    backend = g17p_shim.G17PShimBackend(u, initdata, doorbell, context=context,
                                       adopt=True,
                                       firmware_root=firmware_root)
    if args.reuse_queue_items:
        backend.reuse_queue_items = True

    # Allocating through this space would otherwise start a fresh UAT initialisation and wait for
    # a firmware handoff that cannot complete, because firmware is already running and did its
    # handoff at boot. The boot experiment installs the same absent handoff for the same reason.
    backend.space.use_absent_handoff()

    def clear_render_output():
        extent = {int(k, 16): int(v, 16)
                  for k, v in (attach.get("render_extent") or {}).items()}
        written = {int(v, 16) for v in (attach.get("render_written") or [])}
        measured = []
        for artifact_path in ARTIFACTS.glob("boot_*/boot.json"):
            try:
                artifact_attach = json.loads(artifact_path.read_text()).get("attach") or {}
            except (OSError, ValueError):
                continue
            if artifact_attach.get("render_written"):
                measured.append((len(artifact_attach["render_written"]),
                                 artifact_path, artifact_attach))
        if measured:
            count, artifact_path, artifact_attach = max(
                measured, key=lambda row: row[0])
            if count > len(written):
                written = {int(value, 16)
                           for value in artifact_attach["render_written"]}
                print("  %d-page output region taken from %s"
                      % (len(written), artifact_path.parent.name))
        pages = {va: pa for va, pa in extent.items() if va in written}
        for pa in pages.values():
            p.memset32(pa, 0, 0x4000)
        if pages:
            p.dc_civac(min(pages.values()), 0x4000)
        print("  cleared %d render pages, so only the next dispatch can restore output"
              % len(pages), flush=True)
        return pages

    for spec in args.write64:
        text_addr, separator, text_value = spec.partition(":")
        if not separator:
            raise SystemExit("--write64 requires ADDR:VALUE")
        address = int(text_addr, 0)
        value = int(text_value, 0)
        backend._write_dva(address, value.to_bytes(8, "little"))
        print("write64 %#x = %#018x" % (address, value), flush=True)
    for value in args.raw_message:
        _doorbell_ep.send(GpuMsg(value))
        print("send raw endpoint-0x21 message %#018x" % value, flush=True)

    channels = backend.channels
    print("Channel table: %d entries, %d of them named"
          % (len(channels.entries), sum(1 for e in channels.entries if e["name"])))
    for entry in channels.entries:
        if not entry["name"]:
            continue
        counters = channels.counters(entry)
        print("  %-6s ring %#014x counters %s"
              % (entry["name"], entry["ring_addr"], counters))

    PAIR_TA = "TA_%d" % args.queue_pair
    PAIR_3D = "3D_%d" % args.queue_pair
    PAIR_NAMES = (PAIR_TA, PAIR_3D)

    print("Work queues:")
    for name in PAIR_NAMES:
        try:
            _entry, queue = backend.queue_for(name)
        except Exception as exc:                       # noqa: BLE001
            print("  %-6s unreachable: %s" % (name, exc))
            continue
        indices = queue.indices()
        print("  %-6s at %#014x  pointers %#014x  ring %#014x"
              % (name, queue.address, queue.pointers_addr, queue.item_ring))
        print("         indices done %d read %d write %d"
              % (indices["done"], indices["read"], indices["write"]))

    for spec in args.dump:
        text_addr, _, text_len = spec.partition(":")
        address = int(text_addr, 0)
        length = int(text_len or "0x40", 0)
        try:
            data = backend._read_dva(address, length)
        except Exception as exc:                                  # noqa: BLE001
            print("dump %#x: unreadable: %s" % (address, exc))
            continue
        print("dump %#x (%#x bytes)" % (address, length))
        for offset in range(0, length, 16):
            chunk = data[offset:offset + 16]
            print("  +%04x  %s" % (offset, chunk.hex(" ", 8)))
        if args.dump_dir is not None:
            args.dump_dir.mkdir(parents=True, exist_ok=True)
            output = args.dump_dir / ("%016x.bin" % address)
            output.write_bytes(data)
            print("  saved %s" % output)

    if args.build_submission:
        # The step-3 question: can the backend construct a submission from a command buffer, rather
        # than be handed one somebody else built? Nothing is published here; this reports what it
        # produced so a failure is a message rather than a wedged coprocessor.
        import types as _types

        state = attach.get("submission_state") or {}
        if not state:
            print("The artifact records no submission state; cannot build.")
            return 0
        drm = _types.SimpleNamespace(
            fb_width=2408, fb_height=1506,
            store_pipeline_bind=0, load_pipeline_bind=0x0007800000000040,
            scissor_array=0x100019a0000, encoder_ptr=0x1000018000,
            store_pipeline=0x10001990640, load_pipeline=0x10001990240,
        )
        supplied = {k: (list(v) if isinstance(v, list) else v) for k, v in state.items()}
        # Two earlier attempts at this hung with no output and cost a target recovery each. Wrap
        # the two things the build allocates through, so a hang names the object it is on instead of
        # being indistinguishable from slow progress.
        import functools

        def announce(name, fn):
            @functools.wraps(fn)
            def wrapper(*a, **kw):
                label = a[0] if a and isinstance(a[0], str) else (
                    kw.get("name") or "?")
                print("    %s(%s) ..." % (name, label), flush=True)
                result = fn(*a, **kw)
                print("      -> %s" % (("%#x" % result.addr)
                                       if hasattr(result, "addr") else result),
                      flush=True)
                return result
            return wrapper

        backend._new_render_object = announce("render object",
                                              backend._new_render_object)
        backend.create_bo = announce("bo", backend.create_bo)

        input_snapshot = {}
        if args.diff_render_inputs:
            # The boot leaves its render inputs in place and the backend allocates over the same
            # addresses, so a snapshot here and another after the build names every page whose
            # content the backend generates differently. Those are what a wrong output comes from
            # once the group itself completes.
            _extent = {int(k, 16): int(v, 16)
                       for k, v in (attach.get("render_extent") or {}).items()}
            for path in sorted((ARTIFACTS / "render_after").glob("*.bin")):
                va = int(path.stem, 16)
                pa = _extent.get(va)
                if pa is None:
                    continue
                p.dc_civac(pa, 0x4000)
                input_snapshot[va] = bytes(iface.readmem(pa, 0x4000))
            print("  snapshotted %d render pages before the build" % len(input_snapshot),
                  flush=True)

        if args.graph_arena:
            # The graph has to be built in firmware's space. "auto" walks forward from just past
            # the boot's own items looking for a run of pages that are mapped there and empty:
            # mapped, because firmware has to be able to fetch them, and empty so that nothing
            # already in use is overwritten.
            if args.graph_arena == "auto":
                # Always measured from the boot's own pair, not the pair being submitted on: a
                # pair this run is about to create has no queue to read yet, and it is the boot's
                # objects the arena has to start past in any case.
                highest = 0
                for qname in ("TA_0", "3D_0"):
                    try:
                        _e, _q = backend.queue_for(qname)
                    except Exception:                             # noqa: BLE001
                        continue
                    for address, stride in zip(_q.items(), (0x2240, 0x180, 0x80)):
                        highest = max(highest, address + stride)
                if not highest:
                    print("  no staged items to place the arena past")
                    return 1
                candidate = (highest + 0x3fff) & ~0x3fff
                base = None
                # Bounded deliberately. An unbounded ceiling here turned a failed search into a
                # scan of gigabytes of address space over the proxy, one page at a time, which
                # does not terminate in any useful time. If there is no run within this window
                # there is no reason to think a far-away one is safe to use either.
                ceiling = highest + 0x2000000
                while candidate < ceiling:
                    for page in range(args.arena_pages):
                        page_va = candidate + page * 0x4000
                        try:
                            # Most occupied pages have something in their first bytes, so read a
                            # head first and only pay for the whole page when that is empty. The
                            # full-page read here was the scan's whole cost.
                            head = backend._read_dva(page_va, 0x40)
                            data = head if any(head) else backend._read_dva(page_va, 0x4000)
                        except Exception:                         # noqa: BLE001
                            candidate += (page + 1) * 0x4000
                            break
                        if any(data):
                            candidate += (page + 1) * 0x4000
                            break
                    else:
                        base = candidate
                        break
                if base is None:
                    print("  no free mapped run of %d pages in firmware's space past 0x%x"
                          % (args.arena_pages, highest))
                    return 1
                print("  found %d free mapped pages at 0x%x, 0x%x past the boot's last item"
                      % (args.arena_pages, base, base - highest))
            else:
                base = int(args.graph_arena, 0)
            limit = base + args.arena_pages * 0x4000
            backend.graph_arena(base, limit)
            print("  submission graph arena 0x%x..0x%x, in firmware's own space"
                  % (base, limit), flush=True)

        if args.alternate_queue_pairs and args.queue_pair:
            parser.error("--alternate-queue-pairs uses channel pair 0; do not combine it with "
                         "--queue-pair")

        if args.queue_pair:
            backend.queue_pair = args.queue_pair
            made = backend.create_queue_pair(
                args.queue_pair,
                {"tiling": supplied["tiling_optional"],
                 "fragment": supplied["fragment_optional"]},
                job_list_addr=args.queue_job_list)
            for name in sorted(made):
                record = made[name]
                print("  %s queue %#x%s"
                      % (name, record["queue"],
                         " (already present)" if record["reused"] else " built here"),
                      flush=True)
        elif args.alternate_queue_pairs:
            made = backend.create_muxed_queue_pair(
                1,
                {"tiling": supplied["tiling_optional"],
                 "fragment": supplied["fragment_optional"]})
            for name in sorted(made):
                record = made[name]
                print("  mux pair 1 on %-4s queue %#x grid %d"
                      % (name, record["queue"], record["grid_index"]), flush=True)

        try:
            cmdbuf = g17p_shim.command_buffer_from_drm(drm, **supplied)
            print("  command buffer translated; building", flush=True)
            built = backend.build_submission(cmdbuf)
        except g17p_shim.G17PUnsupported as exc:
            print("The backend refused: %s" % exc)
            return 0
        except Exception as exc:                              # noqa: BLE001
            print("The build failed: %s: %s" % (type(exc).__name__, exc))
            return 1
        if input_snapshot:
            _extent = {int(k, 16): int(v, 16)
                       for k, v in (attach.get("render_extent") or {}).items()}
            changed = []
            for va, before in input_snapshot.items():
                pa = _extent[va]
                p.dc_civac(pa, 0x4000)
                if bytes(iface.readmem(pa, 0x4000)) != before:
                    changed.append(va)
            print("  the build changed %d of %d render pages"
                  % (len(changed), len(input_snapshot)))
            for va in changed[:16]:
                print("      0x%x" % va)
            if len(changed) > 16:
                print("      ... %d more" % (len(changed) - 16))

        if args.submit:
            # Take the boot's staging out first, so the only work in the world is the backend's.
            # Without this the doorbell finds the boot's group at the earlier slots and dispatches
            # that instead, which is what the previous run measured and nearly claimed.
            from m1n1.agx.g17p import (QUEUE_PTR_DONE, QUEUE_PTR_READ,
                                       QUEUE_PTR_WRITE, RING_SLOT_SIZE)
            import struct as _s

            # Keep the boot's item bodies before un-staging. They are the ones that complete, so
            # they are the reference the backend's own bodies get compared against below; the
            # difference is what firmware fetched and declined to run.
            # The pair packs its two optional items into one page 0xc0 apart and its two event
            # items 0x40 apart, so those are the object sizes. Reading 0x180 and 0x80 here ran
            # each comparison off the end of its object and into the neighbouring one, which is
            # where the last "differing" bytes were coming from.
            ITEM_STRIDES = {PAIR_TA: (0x9c0, 0xc0, 0x40), PAIR_3D: (0x2240, 0xc0, 0x40)}
            reference_bodies = {}
            for qname in PAIR_NAMES:
                _e, _q = backend.queue_for(qname)
                bodies = []
                for address, stride in zip(_q.items(), ITEM_STRIDES[qname]):
                    bodies.append((address, stride, backend._read_dva(address, stride)))
                reference_bodies[qname] = bodies
                print("  kept %d reference item bodies for %s" % (len(bodies), qname))

            for qname in PAIR_NAMES if not args.keep_staged else ():
                entry, q = backend.queue_for(qname)
                for offset in (QUEUE_PTR_DONE, QUEUE_PTR_READ, QUEUE_PTR_WRITE):
                    backend._write_dva(q.pointers_addr + offset, _s.pack("<I", 0))
                backend._write_dva(entry["state_addrs"][2], _s.pack("<I", 0))
                # Restore a fresh queue's pointer-only slot zero. queue_for() needs this pointer,
                # but it is metadata rather than a publication; next_free_slot() ignores the
                # pointer when deciding whether slot zero is writable.
                backend._write_dva(entry["ring_addr"], bytes(RING_SLOT_SIZE))
                backend._write_dva(entry["ring_addr"] + g17p.RING_SLOT_QUEUE_PTR,
                                   _s.pack("<Q", q.address))
            print("  cleared the boot's staging; the backend's group is the only work"
                  if not args.keep_staged else
                  "  left the queue indices alone; the backend appends to what is there",
                  flush=True)

            if args.slot_wrap:
                # next_free_slot takes the first slot that is still zero, so it walks forward
                # forever and never reuses one firmware has consumed. This makes it wrap.
                _slot_counter = {}

                def _wrapping_slot(entry):
                    key = entry["ring_addr"]
                    index = _slot_counter.get(key, 0)
                    _slot_counter[key] = index + 1
                    return index % args.slot_wrap

                backend.channels.next_free_slot = _wrapping_slot
                print("  ring slots reused modulo %d" % args.slot_wrap, flush=True)

            # The submitter rings as part of publishing. Hold that back so the fill below lands
            # before firmware is told, then ring by hand.
            _real_doorbell = backend.submitter.doorbell
            if args.fill_items != "none" or args.use_reference_items:
                backend.submitter.doorbell = lambda *a, **k: None

            # Publish what it built, through the backend's own path, and let the caller ring.
            print("  publishing the built submission through the backend", flush=True)
            if args.clear_extent:
                clear_render_output()
            published = backend.submit_register_pair(
                built["tiling_registers"], built["fragment_registers"],
                built["shared"], built["pools"],
                built["tiling_optional"], built["fragment_optional"],
                queue_pair=0 if args.alternate_queue_pairs else None)
            for name in sorted(published or {}):
                entry = published[name]
                if isinstance(entry, dict):
                    print("    %-6s slot %s, write %s -> %s"
                          % (name, entry.get("slot"), entry.get("write_before"),
                             entry.get("write_after")))

            if args.use_reference_items:
                # Same publish, same everything else, but the item ring names the addresses the
                # boot staged rather than the ones the backend built. Filling the bodies made no
                # difference, so this asks whether the address is what firmware is refusing.
                import struct as _st
                for qname in PAIR_NAMES:
                    _e, _q = backend.queue_for(qname)
                    for slot, (address, _stride, _want) in enumerate(
                            reference_bodies.get(qname, [])):
                        backend._write_dva(_q.item_ring + slot * 8, _st.pack("<Q", address))
                    print("  %s item ring renamed to the boot's own addresses" % qname)
                backend.submitter.doorbell = _real_doorbell
                _real_doorbell()
                print("  rang with the boot's item addresses")

            if args.fill_items != "none":
                # Classify each differing byte by the qword it sits in. A qword whose completing
                # value is in firmware's high half is a pointer; everything else is a scalar.
                # The two classes are filled separately because they fail for different reasons:
                # a wrong pointer names the wrong object, a missing scalar names nothing.
                filled = 0
                for qname in PAIR_NAMES:
                    _e, _q = backend.queue_for(qname)
                    built = _q.items()
                    for slot, (address, stride, want) in enumerate(
                            reference_bodies.get(qname, [])):
                        if slot >= len(built):
                            continue
                        got = bytearray(backend._read_dva(built[slot], stride))
                        for base in range(0, stride & ~7, 8):
                            if got[base:base + 8] == want[base:base + 8]:
                                continue
                            value = int.from_bytes(want[base:base + 8], "little")
                            is_pointer = (value >> 40) == 0xfffffc
                            if args.fill_items == "all" or \
                               (args.fill_items == "pointers") == bool(is_pointer):
                                got[base:base + 8] = want[base:base + 8]
                                filled += 1
                        backend._write_dva(built[slot], bytes(got))
                print("  filled %d qwords from the bodies that complete (%s)"
                      % (filled, args.fill_items))
                backend.submitter.doorbell = _real_doorbell
                _real_doorbell()
                print("  rang after filling")

            def watch(label):
                if not args.watch_control:
                    return
                # 0xfffffc20c0830000 is the shared control object the device-control opening
                # registers. Its +0x48 counter is the one a host advances per group.
                try:
                    block = backend._read_dva(0xfffffc20c0830000, 0x60)
                except Exception as exc:                          # noqa: BLE001
                    print("    control unreadable: %s" % exc)
                    return
                import struct as _sw
                fields = _sw.unpack_from("<8I", block, 0x40)
                print("    %-12s control +0x40..0x60 %s"
                      % (label, " ".join("%08x" % value for value in fields)))
                from m1n1.agx import g17p as _g
                # Every channel, not only the pair's. A firmware-produced channel carrying a
                # request the host never answers would look exactly like this stall, and those
                # channels have never been read here.
                for other in backend.channels.entries:
                    counters = backend.channels.counters(other)
                    if any(counters):
                        print("      chan %-8s %s" % (other.get("name") or "?", counters))
                for qname in PAIR_NAMES:
                    entry = backend.channels.by_name(qname)
                    line = "      %-6s ring counters %s" % (
                        qname, backend.channels.counters(entry))
                    try:
                        _e, _q = backend.queue_for(qname)
                        rec = _g.parse_queue_record(
                            backend._read_dva(_q.address, _g.QUEUE_DESCRIPTOR_SIZE))
                        line += ("  event %d busy %d inflight %d has_cmds %d"
                                 "  rptr %d/%d/%d"
                                 % (rec["event_id"], rec["busy"], rec["inflight"],
                                    rec["has_commands"], rec["gpu_rptr1"],
                                    rec["gpu_rptr2"], rec["gpu_rptr3"]))
                        head = _g.parse_job_list(
                            backend._read_dva(rec["job_list_addr"], 0x10),
                            own_address=rec["job_list_addr"])
                        line += ("  joblist@%#x first %#x last %#x %s"
                                 % (rec["job_list_addr"], head["first"], head["last"],
                                    "empty" if head.get("empty") else "populated"))
                    except Exception as exc:                      # noqa: BLE001
                        line += "  (record unreadable: %s)" % exc
                    print(line)
                    # Both halves, not only the tiling one. The fragment queue is the half that
                    # stops fetching, so its announcements are the ones worth comparing.
                    if True:
                        # The announcements themselves, consumed and ignored side by side. This
                        # is the one piece of state this path publishes and never reads back.
                        for slot in range(6):
                            raw = backend._read_dva(
                                entry["ring_addr"] + slot * _g.RING_SLOT_SIZE,
                                _g.RING_SLOT_SIZE)
                            if not any(raw):
                                continue
                            import struct as _ss
                            queue_ptr = _ss.unpack_from("<Q", raw, _g.RING_SLOT_QUEUE_PTR)[0]
                            kind_word = _ss.unpack_from("<I", raw, _g.RING_SLOT_KIND)[0]
                            packed = _ss.unpack_from("<I", raw, _g.RING_SLOT_FLAGS_HEAD)[0]
                            print("        slot %d  queue %#x kind %d  head %d index %d "
                                  "first %d  packed %08x"
                                  % (slot, queue_ptr, kind_word,
                                     packed & _g.RING_HEAD_MASK,
                                     (packed >> _g.RING_QUEUE_INDEX_SHIFT)
                                     & _g.RING_QUEUE_INDEX_MASK,
                                     1 if packed & _g.RING_FIRST_SUBMIT_BIT else 0,
                                     packed))

                # A queue reaching done==write only says firmware retired its
                # items. The scheduler list distinguishes execution (empty) from
                # deferral (populated), so report every created pair as well as
                # the initial pair above.
                for pair_index, queues in sorted(backend.muxed_queue_pairs.items()):
                    if pair_index == 0:
                        continue
                    seen = set()
                    for kind in ("tiling", "fragment"):
                        _entry, queue = queues[kind]
                        if queue.job_list_addr in seen:
                            continue
                        seen.add(queue.job_list_addr)
                        try:
                            head = _g.parse_job_list(
                                backend._read_dva(queue.job_list_addr,
                                                  _g.JOB_LIST_SIZE),
                                own_address=queue.job_list_addr)
                            print("      mux%d joblist@%#x first %#x last %#x %s"
                                  % (pair_index, queue.job_list_addr,
                                     head["first"], head["last"],
                                     "empty" if head.get("empty") else "populated"))
                        except Exception as exc:                  # noqa: BLE001
                            print("      mux%d joblist unreadable: %s"
                                  % (pair_index, exc))

            watch("after 1")

            for round_index in range(1, max(1, args.submit_count)):
                # A real driver submits again on the same queues. Each call builds fresh items at
                # fresh addresses and advances the pool records, so this is a second submission
                # rather than a republication of the first.
                import time as _t
                _t.sleep(0.5)
                control_done = args.control_done_between
                if args.native_control_done:
                    control_done = 2 if round_index == 1 else 1
                if control_done:
                    for _ in range(control_done):
                        # The native control-done message carries payload 0x11 in
                        # the low bits. CHANNEL=0 constructs a different message.
                        _doorbell_ep.send(GpuMsg(0x0084000000000011))
                    print("  sent %d control-done before submission %d"
                          % (control_done, round_index + 1), flush=True)
                    _t.sleep(0.2)
                if args.drain_events:
                    drained = []
                    for _ in range(args.drain_events):
                        try:
                            if not _asc.work_pending():
                                break
                            message = _asc.recv()
                        except Exception as exc:                  # noqa: BLE001
                            drained.append("error %s" % exc)
                            break
                        if message is None:
                            break
                        drained.append(message)
                    print("  drained %d message(s): %s"
                          % (len(drained),
                             ", ".join(str(m) for m in drained[:6]) or "none"),
                          flush=True)
                if args.advance_cursor:
                    import struct as _sc
                    _cursor_addr = 0xfffffc20c0830000 + 0x48
                    _now = _sc.unpack("<I", backend._read_dva(_cursor_addr, 4))[0]
                    backend._write_dva(_cursor_addr,
                                       _sc.pack("<I", _now + args.advance_cursor))
                    print("  control cursor %#x -> %#x"
                          % (_now, _now + args.advance_cursor), flush=True)
                if args.reset_render_state:
                    # The objects the render page table marks as starting zeroed: the two status
                    # pages, the depth bias array, the tilemap, the parameter-buffer metadata and
                    # the tile parameter cache.
                    for name, address, pages in (
                            ("ta_status", 0x1000078000, 1),
                            ("fragment_status", 0x10001a8000, 1),
                            ("depth_bias_array", 0x10001af8000, 1),
                            ("tilemap", 0x10001b0000, 1),
                            ("heapmeta", 0x10001b4000, 1),
                            ("tile_parameter_cache", 0x1000240000, 1)):
                        try:
                            backend._write_dva(address, bytes(0x4000 * pages))
                        except Exception as exc:                  # noqa: BLE001
                            print("    %s not reset: %s" % (name, exc))
                    print("  per-render state zeroed", flush=True)
                if args.clear_extent:
                    clear_render_output()
                if args.fixed_item_index:
                    backend.group_number = 0
                print("  submission %d%s" % (round_index + 1,
                                             " (as item 0)" if args.fixed_item_index else ""),
                      flush=True)
                try:
                    submitted = backend.submit_register_pair(
                        built["tiling_registers"], built["fragment_registers"],
                        built["shared"], built["pools"],
                        built["tiling_optional"], built["fragment_optional"],
                        queue_pair=(round_index % 2)
                        if args.alternate_queue_pairs else None)
                except Exception as exc:                      # noqa: BLE001
                    print("    refused: %s: %s" % (type(exc).__name__, exc))
                    break
                _t.sleep(1.0)
                if args.alternate_queue_pairs:
                    for kind in ("tiling", "fragment"):
                        idx = submitted[kind]["queue"].indices()
                        print("    mux%-2d %-8s done %d read %d write %d"
                              % (round_index % 2, kind, idx["done"],
                                 idx["read"], idx["write"]))
                for qname in PAIR_NAMES:
                    try:
                        _e, _q = backend.queue_for(qname)
                        idx = _q.indices()
                        print("    %-6s done %d read %d write %d"
                              % (qname, idx["done"], idx["read"], idx["write"]))
                    except Exception as exc:                  # noqa: BLE001
                        print("    %-6s unreadable: %s" % (qname, exc))
                watch("after %d" % (round_index + 1))

            # Publishing and rendering are different things and this record has confused them
            # before. Read the queues and compare the output, as the other path does.
            import time as _time
            _time.sleep(1.0)
            for qname in PAIR_NAMES:
                try:
                    _e, q = backend.queue_for(qname)
                    idx = q.indices()
                    print("    %-6s done %d read %d write %d"
                          % (qname, idx["done"], idx["read"], idx["write"]))
                except Exception as exc:                      # noqa: BLE001
                    print("    %-6s unreadable: %s" % (qname, exc))

            # Where the backend's own bodies differ from the ones that complete. Field offsets,
            # not a verdict: a difference is expected wherever an address legitimately differs,
            # and the interesting ones are the fields that are not addresses at all.
            for qname in PAIR_NAMES:
                try:
                    _e, _q = backend.queue_for(qname)
                    built = _q.items()
                except Exception as exc:                          # noqa: BLE001
                    print("  %s items unreadable: %s" % (qname, exc))
                    continue
                for slot, (address, stride, want) in enumerate(reference_bodies.get(qname, [])):
                    if slot >= len(built):
                        print("  %s item %d: nothing published here" % (qname, slot))
                        continue
                    got = backend._read_dva(built[slot], stride)
                    runs, start = [], None
                    for off in range(stride):
                        differs = got[off] != want[off]
                        if differs and start is None:
                            start = off
                        elif not differs and start is not None:
                            runs.append((start, off))
                            start = None
                    if start is not None:
                        runs.append((start, stride))
                    print("  %s item %d (stride 0x%x): %d differing runs, %d bytes"
                          % (qname, slot, stride, len(runs),
                             sum(b - a for a, b in runs)))
                    for a, b in runs[:24]:
                        print("      +0x%04x..0x%04x  want %s  got %s"
                              % (a, b, want[a:b][:16].hex(), got[a:b][:16].hex()))
                    if len(runs) > 24:
                        print("      ... %d more runs" % (len(runs) - 24))

            reference = ARTIFACTS / "render_after"
            extent = {int(k, 16): int(v, 16)
                      for k, v in (attach.get("render_extent") or {}).items()}
            if reference.is_dir() and extent:
                same = differ = absent = 0
                for path in sorted(reference.glob("*.bin")):
                    va = int(path.stem, 16)
                    pa = extent.get(va)
                    if pa is None:
                        absent += 1
                        continue
                    p.dc_civac(pa, 0x4000)
                    if bytes(iface.readmem(pa, 0x4000)) == path.read_bytes()[:0x4000]:
                        same += 1
                    else:
                        differ += 1
                print("  against a working host's own output: %d identical, %d differ, "
                      "%d unmapped here" % (same, differ, absent))
                if input_snapshot:
                    # A retired group that wrote nothing and a retired group that drew the wrong
                    # thing look the same against the reference. This tells them apart.
                    touched = 0
                    for va, before in input_snapshot.items():
                        pa = extent.get(va)
                        if pa is None:
                            continue
                        p.dc_civac(pa, 0x4000)
                        if bytes(iface.readmem(pa, 0x4000)) != before:
                            touched += 1
                    print("  the submission itself changed %d of %d render pages"
                          % (touched, len(input_snapshot)))
            return 0

        print("The backend built a submission from a command buffer:")
        for name in sorted(built):
            value = built[name]
            if isinstance(value, int):
                print("  %-20s %#x" % (name, value))
            elif isinstance(value, (list, tuple)):
                print("  %-20s %d entries" % (name, len(value)))
            else:
                print("  %-20s %s" % (name, type(value).__name__))
        return 0

    if not args.ring:
        print("Attached and read the live firmware's state; nothing was published.")
        return 0

    # The doorbell is a mailbox write to a coprocessor this process did not boot. Constructing the
    # ASC object does not restart it; only its boot sequence would, and that is not called here.
    # The doorbell endpoint the boot experiment registers at 0x21, defined here rather than
    # imported: importing that module would open a second proxy connection. Constructing the ASC
    # does not restart the coprocessor; only its boot sequence would, and that is not called.
    from m1n1.fw.asc import StandardASC
    from m1n1.fw.asc.base import ASCBaseEndpoint
    from m1n1.agx.g17p import MSG_WORK_DOORBELL
    from m1n1.utils import Register64

    class GpuMsg(Register64):
        TYPE = 55, 48

    class DoorbellEndpoint(ASCBaseEndpoint):
        BASE_MESSAGE = GpuMsg
        SHORT = "db"

    class AttachASC(StandardASC):
        ENDPOINTS = dict(StandardASC.ENDPOINTS)
        ENDPOINTS[0x21] = DoorbellEndpoint

    asc = AttachASC(u, int(u.adt["/arm-io/gfx-asc"].get_reg(0)[0]))
    before = {}
    channel_before = {}
    for name in PAIR_NAMES:
        _entry, queue = backend.queue_for(name)
        before[name] = queue.indices()
        channel_before[name] = backend.channels.counters(_entry)
    if args.clear_extent:
        clear_render_output()

    if args.publish:
        # Take the boot's staging back out and put it in again from here. The boot built the
        # objects; this publishes them. Reading the item addresses out of the live ring is how this
        # process learns what the group is, since the artifact records only channel names.
        from m1n1.agx.g17p import (QUEUE_PTR_DONE, QUEUE_PTR_READ, QUEUE_PTR_WRITE,
                                   RING_SLOT_SIZE, EVENT_SUBTYPE_BASE)
        import struct as _struct

        republished = []
        for name, kind, grid in (("TA_0", "tiling", 0), ("3D_0", "fragment", 1)):
            entry, queue = backend.queue_for(name)
            items = queue.items()
            if not items:
                print("  %s has nothing staged; nothing to republish" % name)
                continue
            if not args.keep_staged:
                # Un-stage: indices back to zero, the announced ring slot cleared, producer cleared.
                for offset in (QUEUE_PTR_DONE, QUEUE_PTR_READ, QUEUE_PTR_WRITE):
                    backend._write_dva(queue.pointers_addr + offset, _struct.pack("<I", 0))
                backend._write_dva(entry["ring_addr"], bytes(RING_SLOT_SIZE))
                backend._write_dva(entry["state_addrs"][2], _struct.pack("<I", 0))
            # Keep the queue object read before the clear: its address came from the ring slot,
            # which has just been zeroed, so re-reading it now would follow a null pointer.
            if args.build_items:
                strides = ((0x9c0 if kind == "tiling" else 0x2240), 0x180, 0x80)
                built = []
                for address, stride in zip(items, strides):
                    body = backend._read_dva(address, stride)
                    backend._write_dva(address + stride, body)
                    built.append(address + stride)
                print("  %-6s built its own items at %s"
                      % (name, " ".join("%#x" % v for v in built)))
                items = built
            staged = backend.submitter.stage(
                entry, queue, items, 1,
                slot=None if args.publish_in_place else 0,
                first_submit=True, kind=kind,
                in_place=args.publish_in_place, announce=False,
                event_subtype=EVENT_SUBTYPE_BASE | grid)
            republished.append((name, items, staged))
            print("  %-6s republished %d items from this process, slot %d, write %d -> %d"
                  % (name, len(items), staged["slot"],
                     staged["write_before"], staged["write_after"]))
        if not republished:
            print("Nothing was republished; not ringing.")
            return 0

    print("Ringing the primary's work doorbell from the attached backend")
    # The endpoint objects are created by the ASC's start sequence, which is not run here, so the
    # doorbell endpoint is instantiated directly against the live mailbox.
    doorbell_ep = DoorbellEndpoint(asc, 0x21)
    doorbell_ep.send(GpuMsg(TYPE=MSG_WORK_DOORBELL))
    import time
    time.sleep(1.0)
    for name in PAIR_NAMES:
        _entry, queue = backend.queue_for(name)
        after = queue.indices()
        counters = backend.channels.counters(_entry)
        print("  %-6s done %d -> %d, read %d -> %d, write %d, channel %s -> %s"
              % (name, before[name]["done"], after["done"],
                 before[name]["read"], after["read"], after["write"],
                 channel_before[name], counters))
    # The witness has to be where the doorbell is. The boot process has exited by now, so its own
    # comparison ran before this dispatch and says nothing about it. The render context is in the
    # hardware context table, at the low root, so its pages can be read from here.
    reference = ARTIFACTS / "render_after"
    if not reference.is_dir():
        print("No reference output at %s; queue completion is the only evidence." % reference)
        return 0

    extent = {int(k, 16): int(v, 16) for k, v in (attach.get("render_extent") or {}).items()}
    if not extent:
        print("The boot artifact records no render extent; queue completion is the only evidence.")
        return 0

    same = differ = absent = 0
    for path in sorted(reference.glob("*.bin")):
        va = int(path.stem, 16)
        pa = extent.get(va)
        if pa is None:
            absent += 1
            continue
        p.dc_civac(pa, 0x4000)
        ours = bytes(iface.readmem(pa, 0x4000))
        theirs = path.read_bytes()[:0x4000]
        if ours == theirs:
            same += 1
        else:
            differ += 1
    print("Against a working host's own output: %d identical, %d differ, %d unmapped here"
          % (same, differ, absent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
