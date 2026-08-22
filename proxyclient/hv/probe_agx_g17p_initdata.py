# SPDX-License-Identifier: MIT
"""Dump the live T8140/G17P initialization descriptor tree from the frozen shell.

    import builtins; builtins.exec(open("proxyclient/hv/probe_agx_g17p_initdata.py").read(), globals())

Reads the descriptor root, the objects it references, and the hardware-data
object, saving each object's bytes. Diffing the result against a pre-start
snapshot separates fields the host configures from fields firmware maintains,
because this runs on a guest that has been running work.
"""

import datetime
import json
import pathlib
import struct

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
_ROOT_POINTERS = (0x08, 0x18, 0x20, 0xa8, 0xb0)


def _probe():
    recorder = g17p
    uat, root = recorder.uat, recorder.root

    def read(dva, size):
        data = bytearray()
        while len(data) < size:
            chunk = min(size - len(data), 0x4000 - ((dva + len(data)) & 0x3fff))
            try:
                data.extend(uat.ioread_root(root, dva + len(data), chunk))
            except Exception:
                break
        return bytes(data) if data else None

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("live_initdata_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)

    objects = {}
    blob = bytearray()

    def capture(name, dva, size):
        data = read(dva, size)
        if data is None:
            objects[name] = {"dva": dva, "size": 0, "error": "unreadable"}
            return None
        extent = len(data)
        while extent and data[extent - 1] == 0:
            extent -= 1
        objects[name] = {
            "dva": dva,
            "size": len(data),
            "nonzero_extent": extent,
            "capture_offset": len(blob),
        }
        blob.extend(data)
        return data

    initdata = recorder.initdata_addr
    root_obj = capture("root", initdata, 0x100)
    pointers = {off: struct.unpack_from("<Q", root_obj, off)[0]
                for off in _ROOT_POINTERS}

    capture("root+0x08", pointers[0x08], 0x4000)
    main = capture("main_config", pointers[0x18], 0x800)
    capture("root+0x20", pointers[0x20], 0x1000)
    capture("root+0xa8", pointers[0xa8], 0x100)
    capture("root+0xb0", pointers[0xb0], 0x100)

    hwdata_addr = struct.unpack_from("<Q", main, 0x00)[0]
    capture("hwdata", hwdata_addr, 0x4000)

    # The two addresses the main object repeats, and its five-address array.
    repeated = struct.unpack_from("<Q", main, 0x08)[0]
    capture("main+0x08_target", repeated, 0x100)
    for i in range(5):
        value = struct.unpack_from("<Q", main, 0x254 + i * 8)[0]
        if value:
            capture("main+0x254[%d]" % i, value, 0x100)
    for i, off in enumerate((0x2d0, 0x2e0, 0x2f0)):
        value = struct.unpack_from("<Q", main, off)[0]
        if value:
            capture("main+%#x" % off, value, 0x100)
    tail = struct.unpack_from("<Q", main, 0x594)[0]
    if tail:
        capture("main+0x594_target", tail, 0x100)

    report = {
        "format": "m1n1-t8140-g17p-live-initdata-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "initdata_addr": initdata,
        "root_pointers": {hex(k): v for k, v in pointers.items()},
        "hwdata_addr": hwdata_addr,
        "objects": objects,
        "uat_root": root,
    }
    (out / "initdata.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "objects.bin").write_bytes(bytes(blob))
    print("G17P initdata: %d objects, %d bytes" % (len(objects), len(blob)))
    for name, info in objects.items():
        print("   %-20s %#018x  extent %s"
              % (name, info["dva"], hex(info.get("nonzero_extent", 0))))
    print("G17P initdata: artifact %s" % out)
    return report


initdata_report = _probe()
