# SPDX-License-Identifier: MIT
"""Capture two native partial-render owners before either reaches the GPU.

The selected first render pair is allowed to publish, but its 0x83 doorbell is
held.  A temporary producer hook then waits for the next tiling publication,
commits that publication to memory, captures the coherent two-owner state, and
finally forwards the original native doorbell.  This avoids trying to recreate
firmware-private scheduler state after one owner has already executed.
"""

from m1n1.hv import TraceMode
from m1n1.utils import irange


if "capture" not in globals():
    raise RuntimeError("load capture_agx_g17p_snapshot.py first")
if "outer_submission_recorder" not in globals():
    raise RuntimeError("load trace_agx_g17p_native_partial_accumulate.py first")


full_capture = capture  # noqa: F821
recorder = outer_submission_recorder  # noqa: F821
state = {
    "armed": False,
    "capture_done": False,
    "first_kick": None,
    "mailbox_payload": None,
    "second_ta_seen": False,
    "selected_ta_pa": None,
    "selected_ta_publication_ignored": False,
    "producer_hooks": [],
}


def is_work_kick(message, endpoint_value):
    return (
        message is not None
        and ((int(message) >> 48) & 0xff) == 0x83
        and (int(endpoint_value) & 0xff) == 0x21
    )


def forward_saved_kick():
    saved = state["first_kick"]
    if saved is None:
        raise RuntimeError("two-pending capture has no held work kick")
    if saved["paired"]:
        u.write(saved["address"], saved["value"], saved["width"])  # noqa: F821
    else:
        # Re-publish the payload as well as the endpoint so this remains exact
        # even if another mailbox payload was written while the kick was held.
        u.write(payload_addr, saved["message"], 64)  # noqa: F821
        u.write(endpoint_addr, saved["endpoint"], saved["width"])  # noqa: F821
    print(
        "G17P two-pending forwarded held native work kick %#x endpoint %#x"
        % (saved["message"], saved["endpoint"] & 0xff),
        flush=True,
    )


def capture_and_release(reason):
    if state["capture_done"]:
        return
    saved = state["first_kick"]
    if saved is None:
        return
    state["capture_done"] = True
    print(
        "G17P two-pending coherent boundary reached (%s); capturing before "
        "either owner executes" % reason,
        flush=True,
    )
    hv._agx_g17p_capture_in_progress = True  # noqa: F821
    try:
        full_capture(saved["message"], saved["endpoint"] & 0xff)
    finally:
        hv._agx_g17p_capture_in_progress = False  # noqa: F821
    forward_saved_kick()


def future_ta_producer_hook(address, value, width):
    """Own the next TA publication and make it visible before the snapshot."""
    address = int(address)
    value = int(value)
    u.write(address, value, width)  # noqa: F821
    if state["capture_done"]:
        return

    # This interposer is installed while the selected fragment publication is
    # being recorded, before that render's adjacent TA publication.  Ignore
    # exactly that first write.  The next write is a second owner even when
    # Metal maps both command queues onto the same physical firmware channel.
    if (
        address == state["selected_ta_pa"]
        and not state["selected_ta_publication_ignored"]
    ):
        state["selected_ta_publication_ignored"] = True
        print(
            "G17P two-pending ignored selected pair TA producer at %#x "
            "value=%#x" % (address, value),
            flush=True,
        )
        return

    state["second_ta_seen"] = True
    print(
        "G17P two-pending observed future TA producer at %#x value=%#x"
        % (int(address), int(value)),
        flush=True,
    )
    capture_and_release("second TA producer publication")


def mailbox_hook(address, value, width):
    address = int(address)
    if not isinstance(value, int):
        values = [int(item) for item in value]
        if address == payload_addr and len(values) >= 2:
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
                        "G17P two-pending suppressed first native work kick "
                        "%#x" % message,
                        flush=True,
                    )
                    if state["second_ta_seen"]:
                        capture_and_release("first kick after second TA")
                    return
                if not state["capture_done"]:
                    # A second doorbell itself also proves the second command
                    # has completed its queue publication.
                    capture_and_release("second native work kick")
        u.write(address, value, width)  # noqa: F821
        return

    value = int(value)
    if address == payload_addr:
        state["mailbox_payload"] = value
        u.write(address, value, width)  # noqa: F821
        return
    if address == endpoint_addr:
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
                    "G17P two-pending suppressed first scalar native work "
                    "endpoint for %#x" % int(message),
                    flush=True,
                )
                if state["second_ta_seen"]:
                    capture_and_release("first kick after second TA")
                return
            if not state["capture_done"]:
                capture_and_release("second scalar native work kick")
    u.write(address, value, width)  # noqa: F821


def arm_two_pending_capture():
    if state["armed"]:
        return

    pair = recorder.pending_render_pair
    if pair is None:
        raise RuntimeError("two-pending capture armed without a selected pair")
    selected_ta = next(
        channel
        for channel in recorder.channels
        if channel["name"] == pair["tiling_channel"]
    )
    state["selected_ta_pa"] = int(selected_ta["producer_pa"])

    # Install after the selected first pair has published.  Every TA producer
    # is covered because a second Metal command queue may be assigned to a
    # different physical firmware channel.
    for channel in recorder.channels:
        if not channel["name"].startswith("TA_"):
            continue
        zone = irange(int(channel["producer_pa"]), 4)
        name = "G17PTwoPendingProducer/%s" % channel["name"]
        hv.add_tracer(  # noqa: F821
            zone,
            name,
            mode=TraceMode.HOOK,
            write=future_ta_producer_hook,
        )
        state["producer_hooks"].append((zone, name))

    hv.add_tracer(  # noqa: F821
        irange(payload_addr, 0x10),
        "G17PTwoPendingMailbox",
        mode=TraceMode.HOOK,
        write=mailbox_hook,
    )
    hv.pt_update()  # noqa: F821
    state["armed"] = True
    print(
        "G17P two-pending capture armed: first kick will be held until the "
        "next TA publication (selected %s producer %#x ignored once)"
        % (pair["tiling_channel"], state["selected_ta_pa"]),
        flush=True,
    )


hv._agx_g17p_arm_full_capture = arm_two_pending_capture  # noqa: F821
print("G17P two-pending partial capture interposer loaded", flush=True)
