#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the one-workload native G17P compute capture.

This is intentionally a narrow positive-control experiment.  It boots the
normal clean-room G17P runtime, installs the captured context-3 client graph and
the captured pre-kick firmware graph at their original DVAs, clears the caller
output, and submits one fresh CL2 publication.  Only the output page changing
to the captured add3 result is success.
"""

import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agx_g17p_compute as compact  # noqa: E402
from m1n1.agx import g17p_compute as compute  # noqa: E402

# Keep the normal post-publication scheduler tick enabled for the exact
# outer-ring replay.  The skip mode remains available for diagnostics.
compact.REPLAY_SKIP_FINAL_SCHEDULER_TICK = False


CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260811_204631"
)
CLIENT = CAPTURE / "CL_2"
PAGE = 0x4000
OUTPUT = 0x10000040000
RESOURCE = 0x100000F8000
CDM = 0x100000C8000
SHADER = 0x100000A8000
INPUT_A = 0x10000030000
INPUT_B = 0x10000038000
DESCRIPTOR = 0xFFFFFC20C0358000
OUTER = 0xFFFFFC20C07A1DC0


def page_bytes(directory, manifest_name, blob_name, address):
    records = json.loads((directory / manifest_name).read_text())
    raw = (directory / blob_name).read_bytes()
    page = int(address) & ~(PAGE - 1)
    record = next(item for item in records["pages"]
                  if int(item["dva"]) == page)
    start = int(record["capture_offset"])
    body = raw[start:start + PAGE]
    return body[int(address) & (PAGE - 1):]


def pte_flags(pte):
    return {
        "AttrIndex": (int(pte) >> 2) & 7,
        "AP": (int(pte) >> 6) & 3,
        "SH": (int(pte) >> 8) & 3,
        "AF": (int(pte) >> 10) & 1,
        "nG": (int(pte) >> 11) & 1,
        "PXN": (int(pte) >> 53) & 1,
        "UXN": (int(pte) >> 54) & 1,
        "OS": (int(pte) >> 55) & 1,
    }


def install_client_graph(backend):
    manifest = json.loads((CLIENT / "native_client_pages.json").read_text())
    raw = (CLIENT / "native_client_pages.bin").read_bytes()
    pages = sorted(manifest["pages"], key=lambda item: int(item["dva"]))
    backing = backend.u.memalign(PAGE, len(pages) * PAGE)
    body = bytearray()
    for page in pages:
        start = int(page["capture_offset"])
        body.extend(raw[start:start + PAGE])
    backend.u.iface.writemem(backing, body)
    backend.u.proxy.dc_civac(backing, len(body))

    space = compact.create_compute_context3_space(backend)
    for index, page in enumerate(pages):
        address = int(page["dva"])
        space.uat.iomap_at(
            3, address, backing + index * PAGE, PAGE,
            **pte_flags(page["pte"]),
        )
    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    backend.u.inst("dsb sy; tlbi aside1os, x0; dsb sy", 3 << 48)

    root = space.uat.ttbr0_base
    print("REPLAY client root=%#x first_pte=%#x direct=%r context=%r" % (
        root, int(space.uat.ioperm(3, int(pages[0]["dva"]))),
        space.uat.iotranslate_root(root, int(pages[0]["dva"]), 1),
        space.uat.iotranslate(3, int(pages[0]["dva"]), 1)), flush=True)
    output_pa = space.uat.iotranslate_root(root, OUTPUT, 1)[0][0]
    resource_pa = space.uat.iotranslate_root(root, RESOURCE, 1)[0][0]
    cdm_pa = space.uat.iotranslate_root(root, CDM, 1)[0][0]
    shader_pa = space.uat.iotranslate_root(root, SHADER, 1)[0][0]
    input_a_pa = space.uat.iotranslate_root(root, INPUT_A, 1)[0][0]
    input_b_pa = space.uat.iotranslate_root(root, INPUT_B, 1)[0][0]
    required = {
        "output": output_pa, "resource": resource_pa, "cdm": cdm_pa,
        "shader": shader_pa, "input_a": input_a_pa, "input_b": input_b_pa,
    }
    if any(pa is None for pa in required.values()):
        raise RuntimeError("captured client graph did not map all required objects: %r"
                           % required)

    before = bytes(PAGE)
    backend.u.iface.writemem(output_pa, before)
    backend.u.proxy.dc_civac(output_pa, PAGE)
    expected = struct.unpack(
        "<64f", bytes.fromhex(
            json.loads((CAPTURE / "native_add3_control.json").read_text())[
                "expected_hex"]
        )[:256]
    )
    space.flush()
    backend.u.inst("dsb sy")
    return {
        "space": space,
        "objects": {
            "resource": (RESOURCE, resource_pa),
            "cdm": (CDM, cdm_pa),
            "shader": (SHADER, shader_pa),
            "input_a": (INPUT_A, input_a_pa),
            "input_b": (INPUT_B, input_b_pa),
            "output": (OUTPUT, output_pa),
        },
        "expected": list(expected),
        "output_pa": output_pa,
    }


def install_firmware_graph(backend):
    manifest = json.loads((CLIENT / "pages.json").read_text())
    raw = (CLIENT / "pages.bin").read_bytes()
    # Device-control pages belong to the fresh boot lifecycle, not to the
    # captured client queue.  Replacing them after registration can roll back
    # scheduler state and makes the next class-2 tick crash.  Transplant the
    # queue/descriptor closure first, while retaining those live control pages.
    device_control_kinds = {
        "device_control_first_object",
        "device_control_first_object_child",
    }
    protected_pages = {
        int(compact.SCHEDULER_PAGE) & ~(PAGE - 1),
        int(compact.SHARED_STATE) & ~(PAGE - 1),
        int(compact.SHARED_SUPPORT) & ~(PAGE - 1),
        int(compact.STATUS_A) & ~(PAGE - 1),
        int(compact.STATUS_B) & ~(PAGE - 1),
        int(compact.QUEUE_CONTEXT_HIGH) & ~(PAGE - 1),
    }
    client_pages = {OUTPUT, RESOURCE, INPUT_A, INPUT_B, SHADER}
    pages = sorted(
        (item for item in manifest["pages"]
         if (int(item["dva"]) >> 42) & 1
         or (int(item["dva"]) in {
             0x7000208000, 0x70004D8000, 0x7000220000,
             0x7000228000, 0x7000230000,
         })
         if int(item["dva"]) not in client_pages
         and (int(item["dva"]) & ~(PAGE - 1)) not in protected_pages
         and not ((int(item["dva"]) >> 42) & 1
                  and any(source.get("kind") in device_control_kinds
                          for source in item.get("sources", [])))),
        key=lambda item: int(item["dva"]),
    )
    inspect = {
        int(compact.QUEUE), int(compact.QUEUE_POINTERS), int(compact.ITEM_RING),
        int(compact.DESCRIPTOR), int(compact.OPTIONAL), int(compact.EVENT),
        int(compact.SCHEDULER_PAGE), int(compact.SHARED_STATE),
    }
    for address in sorted(inspect):
        try:
            # The high graph and low queue aliases live in different UAT
            # views.  Try the firmware view first, then the client view for
            # low-address queue pages.
            try:
                current = backend._read_dva(address, PAGE)
            except Exception:
                current = backend.space.uat.readmem(address, PAGE)
            record = next((item for item in manifest["pages"]
                           if int(item["dva"]) == address), None)
            if record is None:
                continue
            start = int(record["capture_offset"])
            captured = raw[start:start + PAGE]
            changed = sum(a != b for a, b in zip(current, captured))
            offsets = [index for index, (a, b) in enumerate(zip(current, captured))
                       if a != b]
            preview = " ".join(
                "%#x:%02x/%02x" % (index, current[index], captured[index])
                for index in offsets[:24])
            print("REPLAY pre-overlay %#x: %d differing bytes [%s]" %
                  (address, changed, preview), flush=True)
        except Exception as exc:
            print("REPLAY pre-overlay %#x: read failed: %s" %
                  (address, exc), flush=True)
    for page in pages:
        address = int(page["dva"])
        compact.map_firmware(backend, address, PAGE)
        start = int(page["capture_offset"])
        backend._write_dva(address, raw[start:start + PAGE])
        backend._clean_dva_range(address, PAGE)
    backend.u.inst("dsb sy")
    return {
        "pages": len(pages),
        "descriptor": DESCRIPTOR,
    }


def install_native_control_tail_objects(backend):
    """Install only objects needed by native control records 25 and 27."""
    manifest = json.loads((CLIENT / "pages.json").read_text())
    raw = (CLIENT / "pages.bin").read_bytes()
    records = {int(item["dva"]): item for item in manifest["pages"]}

    def captured_page(page):
        item = records.get(page)
        if item is None:
            raise RuntimeError("native tail object page %#x is absent" % page)
        start = int(item["capture_offset"])
        return raw[start:start + PAGE]

    # c0870000 is the second half of the scheduler page. Keep its live
    # scheduler header and replace only the object beginning at +0x800.
    scheduler = compact.SCHEDULER_PAGE & ~(PAGE - 1)
    compact.map_firmware(backend, scheduler, PAGE)
    body = captured_page(scheduler)
    backend._write_dva(scheduler + 0x800, body[0x800:])
    backend._clean_dva_range(scheduler + 0x800, PAGE - 0x800)

    control = 0xfffffc20c08c0000
    compact.map_firmware(backend, control, PAGE)
    backend._write_dva(control, captured_page(control))
    backend._clean_dva_range(control, PAGE)
    backend.u.inst("dsb sy")
    print("REPLAY installed native tail objects at %#x and %#x" %
          (scheduler + 0x800, control), flush=True)


def build_client_graph(backend):
    installed = install_client_graph(backend)
    objects = installed["objects"]
    return objects, installed["expected"], CDM + compute.CDM_RECORD_SIZE, installed["space"]


def build_firmware_graph(backend, terminator, *args, **kwargs):
    # Let the existing builder establish a valid queue object and channel
    # bookkeeping, then replace its generated pages with the complete captured
    # pre-kick firmware graph.  The capture's outer record is still published by
    # the normal submitter, so this is a fresh kick rather than a mailbox replay.
    kwargs["registers_override"] = compact.compute_registers(
        resource=RESOURCE, cdm=CDM, robustness=compact.ZERO_PAGE)
    queue = compact._ORIGINAL_BUILD_FIRMWARE_GRAPH(
        backend, terminator, *args, **kwargs)
    # Keep the live lifecycle objects intact through compute binding and class2
    # registration.  The pre-kick firmware image is installed by the trigger
    # wrapper immediately before the final CL2 doorbell.
    compact._REPLAY_FIRMWARE_BACKEND = backend
    return queue


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_replay_minimal_compute.py accepts no arguments")
    if not CLIENT.is_dir():
        raise RuntimeError("missing capture %s" % CLIENT)

    target = json.loads((CLIENT / "target.json").read_text())
    queue = target["queues"][0]
    compact.QUEUE = int(queue["queue_dva"])
    compact.QUEUE_POINTERS = int(queue["queue_pointers"][0])
    compact.ITEM_RING = int(queue["queue_pointers"][1])
    compact.JOB_LIST = int(queue["queue_pointers"][2])
    compact.DESCRIPTOR = DESCRIPTOR
    compact.DESCRIPTOR_LOW = int(queue["inner_entries"][0][0])
    compact.OPTIONAL = int(queue["inner_entries"][0][1])
    compact.EVENT = int(queue["inner_entries"][0][2])
    compact.QUEUE_CONTEXT_HIGH = int(queue["queue_context_dva"])
    native_objects = json.loads(
        (CLIENT / "native_client_pages.json").read_text())["objects"]
    compact.QUEUE_CONTEXT_LOW = int(
        next(item["dva"] for item in native_objects
             if item["name"] == "queue_context_low")
    )
    compact.CHANNEL_CONTROL = compact.QUEUE_CONTEXT_HIGH
    # The channel entry is a separate outer ring from the command queue's
    # inner item ring.  The native capture's CL_2 publication used this exact
    # outer slot; the generic builder otherwise allocates a fresh ring.
    compact.OUTER = int(target["outer_dva"])
    compact.RESOURCE = RESOURCE
    compact.CDM = CDM
    compact.SHADER = SHADER
    compact.BUFFER_A = INPUT_A
    compact.BUFFER_B = INPUT_B
    compact.BUFFER_OUT = OUTPUT
    compact.NATIVE_OUTPUT = OUTPUT
    compact.NATIVE_RESOURCE = RESOURCE
    compact.NATIVE_CDM = CDM
    compact.NATIVE_SHADER = SHADER
    compact.PROBE_TIMEOUT = 0

    descriptor = page_bytes(CLIENT, "pages.json", "pages.bin", DESCRIPTOR)
    qword = lambda offset: struct.unpack_from("<Q", descriptor, offset)[0]
    # The pre-kick descriptor is the authority for the firmware-side graph
    # pointers.  Keep the normal builder's names aligned with it so its
    # post-build checks and the final client-side validation refer to the same
    # captured objects.
    compact.SCHEDULER = qword(0x10)
    compact.SCHEDULER_PAGE = compact.SCHEDULER & ~(PAGE - 1)
    compact.DISPATCH_A = qword(0xF40)
    compact.DISPATCH_B = qword(0xF48)
    compact.STATUS_A = qword(0xF7C)
    compact.STATUS_B = qword(0xF84)
    compact.SHARED_SUPPORT = qword(0xFB2)
    compact.ZERO_PAGE = struct.unpack_from("<Q", descriptor, 0xFCB)[0] & ~(PAGE - 1)
    compact.CDM = CDM
    scheduler_page = page_bytes(CLIENT, "pages.json", "pages.bin",
                                compact.SCHEDULER_PAGE)
    scheduler_state = struct.unpack_from("<Q", scheduler_page, 0)[0]
    compact.SCHEDULER_SLOT = scheduler_state
    compact.SHARED_STATE = scheduler_state & ~0x3

    # This run is a graph replay positive control.  The captured page package
    # is validated structurally by the installer; the generated-path pointer
    # audit would necessarily reject the capture's different allocator layout.
    compact.dump_hardware_uat_slots = lambda _backend: None

    # The captured descriptor is installed by the firmware overlay.  Avoid the
    # generated descriptor's byte-level checks while retaining all runtime setup.
    compact._ORIGINAL_BUILD_FIRMWARE_GRAPH = compact.build_firmware_graph
    compact.build_client_graph = build_client_graph
    compact.build_firmware_graph = build_firmware_graph
    original_trigger = compact.trigger_submission
    native_control_entries = json.loads(
        (CLIENT / "target.json").read_text())["device_control"]["entries"]
    replayed_control_tail = False
    def replay_trigger(front, backend, trigger, channel_name):
        nonlocal replayed_control_tail
        if not replayed_control_tail:
            runtime = front.g17p_runtime
            if runtime is None or "announce_control_body" not in runtime:
                raise RuntimeError("replay has no control-ring announcer")
            install_native_control_tail_objects(backend)
            # The generic lifecycle reaches producer 12.  Reproduce the
            # remaining native pre-kick control records verbatim, including
            # the two later 0x20 registrations and their 0x2e ticks.
            for entry in native_control_entries[12:]:
                runtime["announce_control_body"](
                    bytes.fromhex(entry["hex"]),
                    "replay native control #%d type %#x" %
                    (entry["absolute_index"], entry["u32"][0]))
            replayed_control_tail = True
        install_firmware_graph(backend)
        return original_trigger(front, backend, trigger, channel_name)
    compact.trigger_submission = replay_trigger
    # The source capture is headless and contains no preceding render group.
    # The generic compute probe uses a render activation only to exercise its
    # context-2 bring-up path; omit that unrelated workload here.
    compact.execute_class2_activation_render = lambda *args, **kwargs: None
    original_run_probe = compact.run_probe
    def replay_run_probe(front, backend, trigger="work"):
        # Redirect the channel entry to the captured outer ring after the cold
        # boot channel table exists, but before stage() writes its slot.
        original_by_name = backend.channels.by_name
        def by_name(name):
            entry = original_by_name(name)
            if entry is not None and name == "CL_2":
                print("REPLAY CL_2 outer ring: generated=%#x captured=%#x" %
                      (int(entry["ring_addr"]), compact.OUTER), flush=True)
                entry["ring_addr"] = compact.OUTER
            return entry
        backend.channels.by_name = by_name
        return original_run_probe(front, backend, trigger=trigger)
    compact.run_probe = replay_run_probe
    return compact.main()


if __name__ == "__main__":
    raise SystemExit(main())
