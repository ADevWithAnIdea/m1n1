#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gate the G17P shim backend's allocator layer, without hardware.

``shim.py`` reaches into a backend in a small number of specific ways: it calls ``new`` on
``ctx.gobj`` or ``ctx.pobj``, reads ``_addr`` off what comes back, assigns ``_map``, calls ``push``,
reads ``ctx.pipeline_base``, and calls ``free``. If any of those is missing or behaves differently
from the earlier generations' objects, the front end breaks at a point that costs a hardware run to
discover, so they are checked here against a fake address space instead.

The submission path is not re-checked here; three existing gates already compare the bodies the
model builds against captured submissions byte for byte. What this adds is the layer between those
and the front end.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, relative):
    """Load a module by path.

    By path rather than as ``m1n1.agx.g17p_shim`` because importing the package runs an
    ``__init__`` that pulls in version-dependent construct definitions and raises when no version
    key is set, which has cost this project a debugging session before.
    """
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeSpace:
    """An address space that hands out addresses and remembers bytes."""

    PAGE = 0x4000

    def __init__(self, base=0x1_5000_0000):
        self.va = base
        self.memory = {}
        self.allocations = []

    def alloc(self, size, name, align=None):
        size = (size + self.PAGE - 1) & ~(self.PAGE - 1)
        va, pa = self.va, 0x8000_0000 + self.va
        self.va += size
        self.allocations.append((name, va, size))
        self.memory[pa] = bytearray(size)
        return va, pa

    def alloc_at(self, va, size, name, **flags):
        page_va = va & ~(self.PAGE - 1)
        offset = va - page_va
        map_size = (offset + size + self.PAGE - 1) & ~(self.PAGE - 1)
        page_pa = 0x4000_0000_0000 + page_va
        self.allocations.append((name, va, size, page_va, map_size, flags))
        self.memory[page_pa] = bytearray(map_size)
        return va, page_pa + offset

    def write(self, pa, data):
        self.memory.setdefault(pa, bytearray(len(data)))[:len(data)] = data

    def read(self, pa, size):
        return bytes(self.memory.get(pa, bytearray(size))[:size])


def main():
    failures = []
    checks = [0]

    def check(label, got, want):
        checks[0] += 1
        ok = got == want
        print("  %-52s %s" % (label, "OK" if ok else "FAIL got %r want %r" % (got, want)))
        if not ok:
            failures.append(label)

    shim = load("g17p_shim_standalone", "m1n1/agx/g17p_shim.py")

    print("allocator layer")
    space = FakeSpace()
    ctx = shim.G17PShimContext(space)

    check("context exposes gobj", hasattr(ctx, "gobj"), True)
    check("context exposes pobj", hasattr(ctx, "pobj"), True)
    check("context exposes pipeline_base", hasattr(ctx, "pipeline_base"), True)

    first = ctx.gobj.new(0x1000, name="first")
    second = ctx.gobj.new(0x1000, name="second")
    check("new returns an object with _addr", hasattr(first, "_addr"), True)
    check("addresses are distinct", first._addr != second._addr, True)
    check("addresses ascend", second._addr > first._addr, True)
    check("allocation is page aligned", first._addr % FakeSpace.PAGE, 0)
    check("a page request occupies a page",
          second._addr - first._addr, FakeSpace.PAGE)

    # shim.py assigns _map then calls push, and expects the bytes to reach device memory.
    payload = bytes(range(256)) * 4
    first._map = bytearray(0x1000)
    first._map[:len(payload)] = payload
    first.push(True)
    check("push copies the host mapping to device memory",
          space.read(first._pa, len(payload)), payload)
    check("push marks the object pushed", first._pushed, True)

    device_side = bytes(reversed(payload))
    space.write(first._pa, device_side)
    check("pull reads device memory back",
          first.pull()[:len(device_side)], device_side)

    first.free()
    check("free drops the mapping", first._map, None)

    # The fields shim.py sets on objects it tracks.
    third = ctx.pobj.new(0x4000, name="pipeline")
    third._memfd_offset = 0x1234
    check("objects carry _memfd_offset", third._memfd_offset, 0x1234)
    check("pipeline_base is subtractable", isinstance(ctx.pipeline_base, int), True)

    print("\nfixed render layout")
    check("layout has seven generated objects",
          len(shim.G17P_RENDER_LAYOUT), 7)
    check("encoder uses context offset 0x18000",
          shim.G17P_RENDER_LAYOUT["encoder"]["dva"]
          - shim.G17P_RENDER_CONTEXT_BASE, 0x18000)
    check("heap metadata retains its 0x1000 page offset",
          shim.G17P_RENDER_LAYOUT["heapmeta"]["dva"] % FakeSpace.PAGE,
          0x1000)
    check("status pages use the writable UXN form",
          shim.G17P_RENDER_LAYOUT["fragment_status"]["UXN"], 1)
    check("encoder uses the non-UXN form",
          shim.G17P_RENDER_LAYOUT["encoder"]["UXN"], 0)

    fixed = ctx.gobj.new_at(
        shim.G17P_RENDER_LAYOUT["heapmeta"]["dva"],
        0x4000,
        name="fixed-heapmeta",
        AP=2,
        nG=1,
        UXN=1,
    )
    check("explicit allocation retains its logical DVA",
          fixed._addr, shim.G17P_RENDER_LAYOUT["heapmeta"]["dva"])
    fixed_record = space.allocations[-1]
    check("unaligned heap metadata maps two pages",
          fixed_record[4], 0x8000)

    encoder = ctx.gobj.new_at(
        shim.G17P_RENDER_LAYOUT["encoder"]["dva"],
        0x8c,
        name="fixed-encoder",
        AP=2,
        nG=1,
        UXN=0,
    )
    encoder_payload = bytes(range(0x8c))
    encoder.push(encoder_payload)
    check("push(bytes) writes a generated encoder directly",
          space.read(encoder._pa, len(encoder_payload)), encoder_payload)

    print("\ncolor target descriptors")
    check("2408x1506 raw twiddled allocation size",
          shim.uncompressed_twiddled_size(2408, 1506), 0xe40000)
    texture = (
        0x760ab332, 0x08178496, 0x00008800, 0x80258010,
        0x000eca40, 0x00096010, 0, 0,
    )
    patched_texture = shim.patch_uncompressed_target_descriptor(
        texture, 0x1100080000, 2408, 1506, "texture")
    check("texture record matches the hardware-tested raw form",
          patched_texture[:6],
          (0x760ab332, 0x00178496, 0x10008000,
           0x00258001, 0x00000000, 0x00096000))
    pbe = (
        0x67c6b332, 0x08017849, 0x00008800, 0x80096010,
        0x000eca40, 0x00096010, 0, 0,
    )
    patched_pbe = shim.patch_uncompressed_target_descriptor(
        pbe, 0x1100080000, 2408, 1506, "pbe")
    check("PBE record matches the hardware-tested raw form",
          patched_pbe[:6],
          (0x67c6b332, 0x00017849, 0x10008000,
           0x00096001, 0x00000000, 0x00096000))
    check("retained target state names all five consumers",
          len(shim.G17P_RETAINED_TARGET_DESCRIPTORS), 5)
    attachment = shim.build_raw_twiddled_attachment_page(
        0x10001970000, shim.G17P_RETAINED_TARGET, 2408, 1506)
    check("attachment builder emits one complete page", len(attachment), 0x4000)
    check("attachment builder emits the ten explicit internal links",
          [int.from_bytes(attachment[offset:offset + 8], "little")
           for offset in shim.G17P_ATTACHMENT_POINTERS],
          [0x10001970000 + relative
           for relative in shim.G17P_ATTACHMENT_POINTERS.values()])
    check("attachment builder emits all verified nonzero state",
          sum(bool(byte) for byte in attachment), 273)
    check("attachment builder carries the store-program id",
          int.from_bytes(attachment[0xb84:0xb88], "little"), 0x6f)

    resource_root = shim.build_shader_resource_root_page()
    check("shader-resource root emits one complete page",
          len(resource_root), 0x4000)
    check("shader-resource root emits exactly three pointers",
          [int.from_bytes(resource_root[offset:offset + 8], "little")
           for offset in (0x30, 0x38, 0xa0)],
          [0x10000021a00, 0x10000021900, 0x10001bc0140])
    check("shader-resource root emits all verified nonzero state",
          sum(bool(byte) for byte in resource_root), 21)
    check("shader-resource root carries the measured entry count",
          int.from_bytes(resource_root[4:8], "little"), 0x6f)

    uniform = shim.build_uniform_payload_page()
    check("uniform payload emits one complete page", len(uniform), 0x4000)
    check("uniform payload omits the four dead metadata qwords",
          [uniform[offset:offset + 8] for offset in (0x150, 0x158, 0x168, 0x198)],
          [bytes(8)] * 4)
    check("uniform payload carries measured dimensions",
          [int.from_bytes(uniform[offset:offset + 4], "little")
           for offset in (0x170, 0x1a0, 0x1a4, 0x1d4)],
          [0x45168000, 0x45168000, 0x44bc4000, 0x44bc4000])

    print("\nrefusals")
    # submit now builds what it can, so what matters is that each thing it cannot build is
    # refused for a named reason rather than producing a half-formed submission.
    backend = object.__new__(shim.G17PShimBackend)

    class Cmdbuf:
        pass

    def refusal(label, cmdbuf, expected_word):
        try:
            backend.submit(cmdbuf=cmdbuf)
        except shim.G17PUnsupported as error:
            check("%s: refused naming %s" % (label, expected_word),
                  expected_word in str(error), True)
            print("      %s" % str(error)[:96])
        except Exception as error:  # noqa: BLE001
            check("%s: refuses with G17PUnsupported" % label,
                  type(error).__name__, "G17PUnsupported")

    refusal("no dimensions", None, "dimensions")

    sized = Cmdbuf()
    sized.width, sized.height = 640, 480
    refusal("no pipelines", sized, "pipeline")

    piped = Cmdbuf()
    piped.width, piped.height = 640, 480
    piped.store_pipeline = piped.load_pipeline = 0x1000010000
    piped.store_pipeline_bind = piped.load_pipeline_bind = 0x40
    refusal("no tiler stream", piped, "tiler stream")

    check("G17PUnsupported is a NotImplementedError",
          issubclass(shim.G17PUnsupported, NotImplementedError), True)

    print("\nDRM command buffer adaptation")

    class DRMCmdbuf:
        fb_width, fb_height = 1280, 720
        store_pipeline, load_pipeline = 0x10000, 0x20000
        store_pipeline_bind, load_pipeline_bind = 0x40, 0x41
        scissor_array = 0x10_0032_0000
        depth_bias_array = 0x10_0033_0000
        encoder_ptr = 0x10_0001_8000

    external = {name: shim.G17P_RENDER_CONTEXT_BASE + 0x30_0000 + index * 0x1000
                for index, name in enumerate(
                    shim.G17PCommandBuffer.EXTERNAL_RENDER_STATE)}
    external.update({"shared": 0x2000, "pools": (0x3000, 0x4000),
                     "tiling_optional": {}, "fragment_optional": {}})

    try:
        shim.command_buffer_from_drm(DRMCmdbuf())
    except shim.G17PUnsupported as error:
        # Every piece the DRM buffer does not carry has to be named, or a caller cannot tell
        # what to supply and a zero default would publish work that draws nothing.
        missing = (shim.G17PCommandBuffer.EXTERNAL_RENDER_STATE
                   + shim.G17PCommandBuffer.EXTERNAL_SUBMISSION_STATE)
        check("bare DRM buffer refusal names every missing piece",
              [name for name in missing if name not in str(error)], [])

    adapted = shim.command_buffer_from_drm(DRMCmdbuf(), **external)
    check("fb_width becomes width", adapted.width, 1280)
    check("fb_height becomes height", adapted.height, 720)
    check("store pipeline preserves the aligned G17P address",
          adapted.store_pipeline, 0x10000)
    check("load pipeline preserves the aligned G17P address",
          adapted.load_pipeline, 0x20000)
    based = shim.command_buffer_from_drm(
        DRMCmdbuf(), pipeline_base=shim.G17P_PIPELINE_BASE, **external)
    check("pipeline offsets use the G17P pipeline address family",
          based.load_pipeline, shim.G17P_PIPELINE_BASE + 0x20000)
    check("G17P load bind restores the generation prefix",
          (adapted.store_pipeline_bind, adapted.load_pipeline_bind),
          (0x40, shim.G17P_LOAD_PIPELINE_BIND_PREFIX | 0x41))
    check("the caller's tiler stream address survives",
          adapted.encoder_ptr, 0x10_0001_8000)
    check("the caller's depth-bias array survives",
          adapted.depth_bias_array, 0x10_0033_0000)
    check("supplied render state reaches the buffer",
          adapted.deflake_1, external["deflake_1"])

    # A DRM caller writes its own tiler stream, so build_submission must take an address rather
    # than only parameters it would generate itself.
    ctx_backend = object.__new__(shim.G17PShimBackend)
    ctx_backend.ctx = ctx
    ctx_backend.render_context_base = shim.G17P_RENDER_CONTEXT_BASE
    ctx_backend.render_layout = shim.G17P_RENDER_LAYOUT
    built = ctx_backend.build_submission(adapted)
    check("a caller-built stream is used where it lies",
          built["encoder"], 0x10_0001_8000)
    check("the fragment program still carries the store pipeline",
          (0x15381, 0x10000) in built["fragment_registers"], True)

    print("\n%d checks, %d failed" % (checks[0], len(failures)))
    for label in failures:
        print("  failed: %s" % label)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
