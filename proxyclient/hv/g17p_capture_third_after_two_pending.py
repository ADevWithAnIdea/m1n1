# SPDX-License-Identifier: MIT
"""Batch two native partials, then capture command three before its kick.

The macOS guest does not retire one native partial command by itself under the
hypervisor, while the proven two-pending path does retire both commands after
one held doorbell is released.  Reuse that exact boundary, but reset the outer
recorder instead of taking a snapshot there.  The next producer publication is
therefore command three on the same native queue generation.
"""

import os
import threading

from m1n1.hv import TraceMode
from m1n1.proxy import EXC_RET
from m1n1.utils import irange


if "outer_submission_recorder" not in globals():
    raise RuntimeError("load trace_agx_g17p_native_partial_accumulate.py first")
if not hasattr(hv, "_agx_g17p_arm_full_capture"):  # noqa: F821
    raise RuntimeError("load capture_agx_g17p_snapshot.py first")


recorder = outer_submission_recorder  # noqa: F821
snapshot_arm = hv._agx_g17p_arm_full_capture  # noqa: F821
MAILBOX_HOOK_NAME = "G17PThirdAfterTwoMailbox"
state = {
    "armed": False,
    "batch_released": False,
    "first_kick": None,
    "mailbox_payload": None,
    "second_ta_seen": False,
    "selected_ta_pa": None,
    "selected_ta_publication_ignored": False,
    "producer_hooks": [],
    "bootstrap_pair": None,
    "bootstrap_output": None,
    "diagnostic_scheduled": False,
}
_original_run_shell = hv.run_shell  # noqa: F821
_diagnostic_ack = threading.Event()


def is_work_kick(message, endpoint_value):
    return (
        message is not None
        and ((int(message) >> 48) & 0xff) == 0x83
        and (int(endpoint_value) & 0xff) == 0x21
    )


def forward_saved_kick():
    saved = state["first_kick"]
    if saved is None:
        raise RuntimeError("third-command batch has no held work kick")
    if saved["paired"]:
        u.write(saved["address"], saved["value"], saved["width"])  # noqa: F821
    else:
        u.write(payload_addr, saved["message"], 64)  # noqa: F821
        u.write(endpoint_addr, saved["endpoint"], saved["width"])  # noqa: F821
    print(
        "G17P third-command batch forwarded held two-command kick %#x"
        % saved["message"],
        flush=True,
    )


def reset_recorder_for_third():
    """Forget the bootstrap pair while retaining its physical producer traps."""
    recorder.closure_captured.clear()
    recorder.closure_done = False
    recorder.closure_skipped.clear()
    recorder.render_filter_skipped.clear()
    recorder.target_render_matched = False
    recorder.target_render_matches_seen = 0
    recorder.pending_render_pair = None
    recorder.pending_mailbox_capture = None
    recorder.pending_render_output_capture = None
    recorder.pending_native_client_capture = None
    recorder.pending_explicit_completion_capture = None
    recorder.write_metadata()


def release_bootstrap_batch(reason):
    if state["batch_released"] or state["first_kick"] is None:
        return
    state["batch_released"] = True
    reset_recorder_for_third()
    hv._agx_g17p_arm_full_capture = snapshot_arm  # noqa: F821
    # This hook writes ordinary later doorbells through.  Remove it before the
    # command-three snapshot hook is armed so it cannot deliver that kick first.
    hv.del_tracer(  # noqa: F821
        irange(payload_addr, 0x10), MAILBOX_HOOK_NAME  # noqa: F821
    )
    hv.pt_update()  # noqa: F821
    print(
        "G17P third-command batch boundary reached (%s); recorder reset for "
        "the next native partial publication" % reason,
        flush=True,
    )
    forward_saved_kick()
    schedule_completion_diagnostic()


def schedule_completion_diagnostic():
    """Stop after the released work has had time to update queue/output state."""
    if state["diagnostic_scheduled"]:
        return
    state["diagnostic_scheduled"] = True

    def worker():
        if _diagnostic_ack.wait(5.0):
            return
        device = os.environ["M1N1DEVICE"].split(":", 1)[0]
        for _ in range(10):
            fd = os.open(device, os.O_WRONLY | os.O_NOCTTY)
            try:
                os.write(fd, b"!")
            finally:
                os.close(fd)
            if _diagnostic_ack.wait(0.1):
                return

    threading.Thread(
        target=worker,
        name="g17p-third-completion-diagnostic",
        daemon=True,
    ).start()


def diagnostic_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    if (
        state["diagnostic_scheduled"]
        and entry_msg == "Entering hypervisor shell"
    ):
        from m1n1.agx import g17p

        _diagnostic_ack.set()
        pair = state["bootstrap_pair"]
        for kind in ("tiling", "fragment"):
            snapshot = recorder.read_queue_snapshot(pair[kind + "_queue"])
            pointers = g17p.parse_queue_pointers(
                bytes.fromhex(snapshot["queue_state_hex"])
            )
            record = g17p.parse_queue_record(
                bytes.fromhex(snapshot["queue_info_hex"])
            )
            print(
                "G17P released-batch diagnostic %s queue=%#x "
                "indices=%r busy=%#x commands=%#x inflight=%#x"
                % (
                    kind,
                    pair[kind + "_queue"],
                    pointers,
                    record["busy"],
                    record["has_commands"],
                    record["inflight"],
                ),
                flush=True,
            )

        pending = state["bootstrap_output"]
        changed = 0
        nonzero = 0
        for page in pending["pages"]:
            pa = int(page["pa"])
            hv.p.dc_ivac(pa, 0x4000)  # noqa: F821
            current = bytes(hv.iface.readmem(pa, 0x4000))  # noqa: F821
            offset = int(page["capture_offset"])
            before = pending["producer_blob"][offset:offset + 0x4000]
            changed += sum(a != b for a, b in zip(current, before))
            nonzero += sum(byte != 0 for byte in current)
        print(
            "G17P released-batch diagnostic output changed=%d nonzero=%d "
            "pages=%d" % (changed, nonzero, len(pending["pages"])),
            flush=True,
        )
        return EXC_RET.EXIT_GUEST
    return _original_run_shell(entry_msg, exit_msg)


def future_ta_producer_hook(address, value, width):
    address = int(address)
    value = int(value)
    u.write(address, value, width)  # noqa: F821
    if state["batch_released"]:
        return
    if (
        address == state["selected_ta_pa"]
        and not state["selected_ta_publication_ignored"]
    ):
        state["selected_ta_publication_ignored"] = True
        print(
            "G17P third-command batch ignored bootstrap TA producer at %#x "
            "value=%#x" % (address, value),
            flush=True,
        )
        return
    state["second_ta_seen"] = True
    print(
        "G17P third-command batch observed second TA producer at %#x value=%#x"
        % (address, value),
        flush=True,
    )
    # Match the already output-positive two-pending capture exactly: once the
    # second TA producer is visible, all of that queue's prior writes and cache
    # maintenance have completed, and the held first doorbell admits both
    # pending commands. Waiting for a second doorbell here kept both command
    # buffers outstanding long enough for Metal's two-buffer queue limit to
    # block command three before it could publish.
    release_bootstrap_batch("second TA producer publication")


def mailbox_hook(address, value, width):
    address = int(address)
    if not isinstance(value, int):
        values = [int(item) for item in value]
        if address == payload_addr and len(values) >= 2:  # noqa: F821
            message, endpoint_value = values[:2]
            state["mailbox_payload"] = message
            if is_work_kick(message, endpoint_value):
                if state["first_kick"] is None:
                    state["first_kick"] = {
                        "paired": True,
                        "address": address,
                        "value": value,
                        "width": width,
                        "message": message,
                        "endpoint": endpoint_value,
                    }
                    print(
                        "G17P third-command batch suppressed first native work "
                        "kick %#x" % message,
                        flush=True,
                    )
                    if state["second_ta_seen"]:
                        release_bootstrap_batch("first kick after second TA")
                    return
                if state["second_ta_seen"] and not state["batch_released"]:
                    release_bootstrap_batch("second work kick")
                    u.write(address, value, width)  # noqa: F821
                    print(
                        "G17P third-command batch forwarded second native "
                        "work kick %#x" % message,
                        flush=True,
                    )
                    return
        u.write(address, value, width)  # noqa: F821
        return

    value = int(value)
    if address == payload_addr:  # noqa: F821
        state["mailbox_payload"] = value
        u.write(address, value, width)  # noqa: F821
        return
    if address == endpoint_addr:  # noqa: F821
        message = state.get("mailbox_payload")
        if is_work_kick(message, value):
            if state["first_kick"] is None:
                state["first_kick"] = {
                    "paired": False,
                    "address": address,
                    "value": value,
                    "width": width,
                    "message": int(message),
                    "endpoint": value,
                }
                print(
                    "G17P third-command batch suppressed first scalar work "
                    "kick %#x" % int(message),
                    flush=True,
                )
                return
            if state["second_ta_seen"] and not state["batch_released"]:
                release_bootstrap_batch("second scalar work kick")
                u.write(payload_addr, int(message), 64)  # noqa: F821
                u.write(address, value, width)  # noqa: F821
                print(
                    "G17P third-command batch forwarded second scalar work "
                    "kick %#x" % int(message),
                    flush=True,
                )
                return
    u.write(address, value, width)  # noqa: F821


def arm_bootstrap_batch():
    if state["armed"]:
        return
    pair = recorder.pending_render_pair
    if pair is None:
        raise RuntimeError("third-command batch armed without selected pair")
    selected_ta = next(
        channel
        for channel in recorder.channels
        if channel["name"] == pair["tiling_channel"]
    )
    state["selected_ta_pa"] = int(selected_ta["producer_pa"])
    state["bootstrap_pair"] = dict(pair)
    state["bootstrap_output"] = recorder.pending_render_output_capture

    for channel in recorder.channels:
        if not channel["name"].startswith("TA_"):
            continue
        zone = irange(int(channel["producer_pa"]), 4)
        name = "G17PThirdAfterTwoProducer/%s" % channel["name"]
        hv.add_tracer(  # noqa: F821
            zone,
            name,
            mode=TraceMode.HOOK,
            write=future_ta_producer_hook,
        )
        state["producer_hooks"].append((zone, name))

    hv.add_tracer(  # noqa: F821
        irange(payload_addr, 0x10),  # noqa: F821
        MAILBOX_HOOK_NAME,
        mode=TraceMode.HOOK,
        write=mailbox_hook,
    )
    hv.pt_update()  # noqa: F821
    state["armed"] = True
    print(
        "G17P third-command batch armed: hold the first kick through the "
        "second TA publication, then capture the next pair",
        flush=True,
    )


hv._agx_g17p_arm_full_capture = arm_bootstrap_batch  # noqa: F821
hv.run_shell = diagnostic_run_shell  # noqa: F821
print("G17P third-after-two pending interposer loaded", flush=True)
