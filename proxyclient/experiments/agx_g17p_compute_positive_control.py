#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay one complete own-shader compute payload as a positive control.

The compact add3 probe deliberately constructs every client object itself, but
it currently omits the uniform/USC object that binds a compute shader's argument
buffer.  This experiment keeps the generated firmware queue and work item while
replaying every GPU-visible BO from the clean-room RT-9 ``t_256_r32`` capture at
its original DVA.  The captured final dispatch reads a known 256x256 R32 texture
and writes 32 caller-visible words.  Its output is cleared before publication;
only the exact 32-word physical result counts as execution.

This is a diagnostic substitution ladder, not the final zero-capture path.
"""

import pathlib
import re
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import agx_g17p_compute as compact  # noqa: E402


CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/public/agx-re/experiments/"
    "RT-9-desc-tiling-pass2/raw/t_256_r32"
)
HEX_LINE = re.compile(r"^([0-9a-fA-F]{8}):\s+(.*)$")

UNIFORM = 0x10000000000
HEAP = 0x10000018000
OUTPUT = 0x1000001C500
TEXTURE = 0x10000080000
CONTROL = 0x100000C8000
SHADER = 0x100000D8000
CDM = 0x100000F8000
RESOURCE = 0x10000128000
PAGE = 0x4000

# One base capture per real mapping.  The many 0x10000018xxx files are shifted
# aliases of HEAP and must not be installed as independent physical mappings.
CAPTURED_BOS = (
    (UNIFORM, "*va10000000000_*", 0x10000, "uniform_usc"),
    (HEAP, "*va10000018000_*", 0x20000, "client_heap"),
    (0x10000040000, "*va10000040000_*", 0x10000, "texture_metadata"),
    (0x10000058000, "*va10000058000_*", 0x20000, "zero_resource"),
    (TEXTURE, "*va10000080000_*", 0x40000, "texture_backing"),
    (CONTROL, "*va100000c8000_*", 0x8000, "compute_control"),
    (SHADER, "*va100000d8000_*", 0x8000, "shader"),
    (0x100000E8000, "*va100000e8000_*", 0x8000, "shader_aux"),
    (CDM, "*va100000f8000_*", 0x8000, "cdm"),
    (0x10000108000, "*va10000108000_*", 0x8000, "cdm_aux_a"),
    (0x10000118000, "*va10000118000_*", 0x8000, "cdm_aux_b"),
    (RESOURCE, "*va10000128000_*", 0xC000, "resource"),
    (0x6F00000000, "*va6f00000000_*", 0x4000, "guard"),
)


def load_hex(pattern):
    matches = list(CAPTURE.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError("capture pattern %r matched %d files" % (
            pattern, len(matches)))
    data = bytearray()
    for line in matches[0].read_text().splitlines():
        match = HEX_LINE.match(line)
        if match is None:
            continue
        offset = int(match.group(1), 16)
        body = bytes.fromhex(match.group(2).replace(" ", ""))
        if len(data) < offset + len(body):
            data.extend(bytes(offset + len(body) - len(data)))
        data[offset:offset + len(body)] = body
    return bytes(data)


def ensure_client_mapping(backend, address, size, name, read_only=False):
    """Keep live pages and fill only holes in a partially mapped BO range."""
    first = address & ~(PAGE - 1)
    last = (address + size + PAGE - 1) & ~(PAGE - 1)
    added = 0
    for page in range(first, last, PAGE):
        translated = backend.space.uat.iotranslate(
            backend.space.context, page, PAGE)
        if translated and translated[0][0] is not None:
            continue
        pa = backend.u.memalign(PAGE, PAGE)
        backend.u.proxy.memset32(pa, 0, PAGE)
        backend.space.uat.iomap_at(
            backend.space.context, page, pa, PAGE,
            AttrIndex=compact.MemoryAttr.Shared, AP=2, nG=1,
            UXN=0 if read_only else 1, OS=1,
        )
        added += 1
    if added:
        backend.space.uat.flush_dirty()
        backend.space.uat.invalidate_cache()
        backend.u.inst("dsb sy")
    translated = backend.space.uat.iotranslate(
        backend.space.context, address, size)
    if (not translated or any(pa is None for pa, _span in translated)
            or sum(span for _pa, span in translated) < size):
        raise RuntimeError("%s DVA %#x remains partially unmapped" % (
            name, address))
    return address, translated[0][0]


def build_replayed_client_graph(backend):
    objects = {}
    mapped = {}
    captured = {}
    for address, pattern, size, name in CAPTURED_BOS:
        body = load_hex(pattern)
        if len(body) > size:
            raise RuntimeError("%s capture is larger than its mapping" % name)
        dva, pa = ensure_client_mapping(
            backend, address, size, name,
            read_only=name in ("shader", "cdm"),
        )
        # Cold boot's render context already maps much of this native client
        # DVA window.  Its backing is not guaranteed physically contiguous, so
        # preserve the mapping and write through the UAT rather than treating
        # the first translated PA as the base of the whole BO.
        backend._write_dva(address, body)
        mapped[address] = (dva, pa, size)
        captured[address] = body

    output_offset = OUTPUT - HEAP
    expected_bytes = captured[HEAP][output_offset:output_offset + 0x100]
    expected_words = struct.unpack("<32I", expected_bytes[:0x80])
    if expected_words != tuple(
            0xA0000000 | (y << 14) | x
            for y in range(4) for x in range(8)):
        raise RuntimeError("captured texture-read output is not the known pattern")

    backend._write_dva(OUTPUT, bytes(0x100))
    backend.space.flush()
    for address, _pattern, size, _name in CAPTURED_BOS:
        backend._clean_dva_range(address, size)
    backend.u.inst("dsb sy")

    def physical(address):
        translated = backend.space.uat.iotranslate(
            backend.space.context, address, 1)
        if not translated or translated[0][0] is None:
            raise RuntimeError("replayed DVA %#x is not translated" % address)
        return translated[0][0]

    resource_pa = physical(RESOURCE)
    texture_pa = physical(TEXTURE)
    uniform_pa = physical(UNIFORM)
    shader_pa = physical(SHADER)
    output_pa = physical(OUTPUT)
    objects.update({
        "resource": (RESOURCE, resource_pa),
        "input_a": (TEXTURE, texture_pa),
        "input_b": (UNIFORM, uniform_pa),
        "output": (OUTPUT, output_pa),
        "shader": (SHADER, shader_pa),
    })
    # Reuse compact.run_probe's strict 256-byte comparison without weakening
    # it: reinterpret the exact expected bytes in the same representation.
    expected = list(struct.unpack("<64f", expected_bytes))
    return objects, expected, CDM + 0x2C


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_compute_positive_control.py accepts no arguments")
    if not CAPTURE.is_dir():
        raise RuntimeError("missing clean-room RT-9 capture %s" % CAPTURE)

    compact.SHADER = SHADER
    compact.RESOURCE = RESOURCE
    compact.CDM = CDM
    compact.BUFFER_A = TEXTURE
    compact.BUFFER_B = UNIFORM
    compact.BUFFER_OUT = OUTPUT
    compact.PROBE_TIMEOUT = 0
    compact.build_client_graph = build_replayed_client_graph
    return compact.main()


if __name__ == "__main__":
    raise SystemExit(main())
