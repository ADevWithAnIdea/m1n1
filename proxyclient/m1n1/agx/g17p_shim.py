# SPDX-License-Identifier: MIT
"""A G17P backend behind the interface ``shim.py`` drives.

``DRMAsahiShim`` is written against the earlier generations' objects: it allocates buffers through
``renderer.ctx.gobj`` and ``renderer.ctx.pobj``, reads ``ctx.pipeline_base``, and submits through a
renderer. This provides the same surface for T8140/G17P, built on the pieces that already exist and
are checked against captured submissions: ``G17PAddressSpace`` for allocation and mapping,
``G17PChannels`` and ``G17PQueue`` for the channel table, ``G17PSubmitter`` for publication, and
``G17PWorkBuilder`` for the bodies a submission needs.

What is real here: device address-space setup, buffer allocation at real device addresses with a
host mapping, channel and queue discovery, command-buffer translation into ordered TA/fragment
register programs and a tiler stream, publication, and completion polling. The first generated
workload executes and fully completes on hardware when its render objects use the coherent layout
below.

What remains external is named rather than faked: compiled load/store shader pipelines and context
objects whose construction is not yet decoded must be supplied by the caller.
"""

import os
import struct

# The backend's own dependencies are imported when a backend is constructed, not at module
# import. The allocator layer below needs none of them, and importing the package eagerly pulls
# in version-dependent construct definitions that raise when no version key is set, which would
# make this module unloadable in a gate that has no hardware to talk to.

__all__ = [
    "G17PShimBackend",
    "G17PShimContext",
    "G17PShimObject",
    "G17PUnsupported",
    "G17PCommandBuffer",
    "command_buffer_from_drm",
    "G17P_RENDER_CONTEXT_BASE",
    "G17P_RENDER_LAYOUT",
    "G17P_GRAPH_ARENA_BASE",
    "G17P_GRAPH_ARENA_SIZE",
    "G17P_LOAD_PIPELINE_BIND_PREFIX",
    "G17P_RETAINED_TARGET",
    "G17P_RETAINED_TARGET_DESCRIPTORS",
    "build_raw_twiddled_attachment_page",
    "build_linear_bgra8_target_descriptor",
    "build_raw_twiddled_target_descriptor",
    "patch_uncompressed_target_descriptor",
    "uncompressed_twiddled_size",
]

# Where the shim's buffers go. Separate from the ranges a replayed world occupies so a backend
# allocation can never land on firmware state restored from a capture.
SHIM_BASE_VA = 0x15_0000_0000
G17P_RENDER_CONTEXT_BASE = 0x10_0000_0000
G17P_PIPELINE_BASE = 0x100_0000_0000
G17P_PIPELINE_START = G17P_PIPELINE_BASE + 0x0001_0000
G17P_USER_VA_END = 1 << 48
G17P_GRAPH_ARENA_BASE = 0xfffffc20c0668000
G17P_GRAPH_ARENA_SIZE = 32 * 0x4000
# The legacy DRM-shim UAPI exposes only the low 32 bits of this register. On
# G17P the hardware-verified clear/load binding carries this fixed upper word.
G17P_LOAD_PIPELINE_BIND_PREFIX = 0x0007800000000000
# Five independently consumed records describe the retained pass's color
# target. The two texture records feed LOAD/RENDER and the three PBE records
# feed STORE. Hardware testing established that all five must agree when the
# private lossless-compression metadata is disabled.
G17P_RETAINED_TARGET = 0x100_0008_8000
G17P_RETAINED_TARGET_DESCRIPTORS = (
    (0x100_0197_0020, "texture"),
    (0x100_0197_0320, "texture"),
    (0x100_0197_0620, "pbe"),
    (0x100_0197_08e0, "pbe"),
    (0x100_0002_0220, "pbe"),
)
# Hardware-captured descriptor templates for the retained 2408x1506 pass. The
# address and dimensions are replaced by build_raw_twiddled_target_descriptor;
# the remaining format bits select the layout consumed by the retained BG/EOT
# programs. A linear descriptor with those programs retires but writes nothing.
G17P_RAW_TWIDDLED_TEMPLATES = {
    "texture": (
        0x760ab332, 0x08178496, 0x00008800, 0x80258010,
        0x000eca40, 0x00096010, 0, 0,
    ),
    "pbe": (
        0x67c6b332, 0x08017849, 0x00008800, 0x80096010,
        0x000eca40, 0x00096010, 0, 0,
    ),
}

# The single-color attachment is a linked LOAD/RENDER/STORE object. These are
# the only full pointers in it; all point to subobjects in the same page.
G17P_ATTACHMENT_POINTERS = {
    0x000: 0x020,
    0x008: 0x120,
    0x160: 0x168,
    0x300: 0x320,
    0x308: 0x420,
    0x460: 0x468,
    0x600: 0x620,
    0x820: 0x828,
    0x8c0: 0x8e0,
    0xae0: 0xae8,
}

# Hardware-tested BGRA8 state surrounding the four in-page surface records.
# The pointer, target and dimension fields are generated separately. Remaining
# values are format, load/clear and store-program controls; several bit-level
# meanings remain unknown, but none is an address, size or live counter.
G17P_ATTACHMENT_BGRA8_STATE = {
    0x040: 0x76888ca2, 0x044: 0x00178496, 0x048: 0x0eeee000,
    0x120: 0x000e0000, 0x124: 0x00000340,
    0x140: 0x60000000, 0x144: 0x0000035b,
    0x168: 0x0000000a, 0x16c: 0x00000003,
    0x1f0: 0x3f800000, 0x1fc: 0x3f800000,
    0x208: 0x3f800000, 0x214: 0x3f800000,
    0x2d0: 0x0010008f, 0x2d4: 0x0010808c,
    0x2f0: 0x00410003,

    0x340: 0x76888ca2, 0x344: 0x00178496, 0x348: 0x0eeee000,
    0x420: 0x000e0000, 0x424: 0x00000340,
    0x440: 0x60000000, 0x444: 0x0000035b,
    0x468: 0x0100000a,
    0x4f0: 0x3f800000, 0x4fc: 0x3f800000,
    0x508: 0x3f800000, 0x514: 0x3f800000,
    0x5d0: 0x0010008f, 0x5d4: 0x0010808c,
    0x5f0: 0x00410003,

    0x608: 0xffffffff, 0x60c: 0xffffffff,
    0x610: 0xffffffff, 0x614: 0xffffffff,
    0x618: 0xffffffff, 0x61c: 0xffffffff,
    0x640: 0x67e48ca2, 0x644: 0x00017849, 0x648: 0x0eeee000,
    0x82c: 0x10020f00, 0x830: 0x10020c00,
    0x874: 0x00000003, 0x878: 0x00400101,
    0x880: 0x00000008, 0x8bc: 0xffffffff,

    0x8c8: 0xffffffff, 0x8cc: 0xffffffff,
    0x8d0: 0xffffffff, 0x8d4: 0xffffffff,
    0x8d8: 0xffffffff, 0x8dc: 0xffffffff,
    0x900: 0x67e48ca2, 0x904: 0x00017849, 0x908: 0x0eeee000,
    0xaec: 0x10020f00, 0xaf0: 0x10020c00,
    0xb34: 0x00000001, 0xb38: 0x00400101,
    0xb40: 0x00000008, 0xb7c: 0xffffffff,
    0xb84: 0x0000006f,
    0xb88: 0x00058000, 0xb8c: 0x00058000,
    0xb90: 0x60000000, 0xb98: 0x00058000,
}

# Root of the retained shader-resource payload. The three full pointers are
# explicit: two select compiler records in the graphics code BO and one names
# the caller's uniform payload. The remaining words are measured format/range
# state; none is a pointer or a live queue counter.
G17P_SHADER_RESOURCE_ROOT_STATE = {
    0x04: 0x0000006f,
    0x08: 0x00058000,
    0x0c: 0x00058000,
    0x10: 0x60000000,
    0x18: 0x00058000,
    0x40: 0x3f000000,
    0x44: 0x3f000000,
}
G17P_SHADER_RESOURCE_CODE_OFFSETS = {
    0x30: 0x21a00,
    0x38: 0x21900,
}
G17P_SHADER_RESOURCE_UNIFORM_OFFSET = 0xa0
G17P_SHADER_RESOURCE_UNIFORM_PAYLOAD_OFFSET = 0x140

# Scalar portion of the render uniform payload. The four address-looking qwords
# deliberately do not appear here: the hardware probe showed that they are
# dead metadata. Width/height are the only fields parameterized by the caller.
G17P_UNIFORM_SCALARS = {
    0x100: 0x3a5a740e, 0x114: 0xbaae4c41,
    0x130: 0x48da73ee, 0x134: 0xc92e4c31,
    0x13c: 0x3f800000, 0x14c: 0x3f800000,
    0x164: 0x3c000000, 0x17c: 0x3f800000,
    0x180: 0x00000068, 0x194: 0x3c000000,
    0x1ac: 0x3f800000, 0x1b8: 0x91c66010,
    0x1bc: 0x0002480b, 0x1c4: 0x3c000000,
    0x1cc: 0x00000707, 0x1dc: 0x3f800000,
    0x1e8: 0x00000001, 0x1f4: 0x3c000000,
    0x200: 0x00010000, 0x204: 0x00020002, 0x208: 0x00000003,
}
# A complete command buffer on fresh physical backing renders and writes both
# completion records with this layout. Independently relocating its members does
# not yet preserve fragment completion, so initial bring-up reserves it as a unit.
# UXN is functional GPU permission state on UAT: firmware-filled/status pages use
# the 0x00c0... PTE form, while encoder/depth pages use 0x0080....
G17P_RENDER_LAYOUT = {
    "tilemap": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x1B0000,
        "UXN": 1,
    },
    "tile_parameter_cache": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x240000,
        "UXN": 1,
    },
    "heapmeta": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x1B5000,
        "UXN": 1,
    },
    "ta_status": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x078000,
        "UXN": 1,
    },
    "fragment_status": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x1A8000,
        "UXN": 1,
    },
    "depth_bias_array": {
        "dva": 0x100_01AF_8000,
        "UXN": 0,
    },
    "encoder": {
        "dva": G17P_RENDER_CONTEXT_BASE + 0x018000,
        "UXN": 0,
    },
}


def _sibling(name):
    """Import a module beside this one, whether or not the package can be imported.

    The gates load this file on its own, because importing ``m1n1.agx`` runs an ``__init__`` that
    needs a version key nothing here sets. A relative import fails in that case, so fall back to
    loading the sibling by path.
    """
    try:
        import importlib
        return importlib.import_module("." + name, __package__ or "m1n1.agx")
    except Exception:
        import importlib.util
        import pathlib
        import sys

        if name in sys.modules:
            return sys.modules[name]
        path = pathlib.Path(__file__).resolve().parent / (name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
SHIM_CONTEXT = 1


class G17PUnsupported(NotImplementedError):
    """Raised for a front-end operation this part's ABI is not decoded far enough to serve."""


class G17PCommandBuffer:
    """What ``build_submission`` consumes, as plain attributes.

    The DRM command buffer and this one are different shapes, and the difference is the honest
    measure of how far the front end reaches: everything below that the DRM buffer does not carry
    is state a working submission still needs from somewhere else.
    """

    # What a DRM command buffer supplies directly, as (this name, DRM name).
    FROM_DRM = (
        ("width", "fb_width"),
        ("height", "fb_height"),
        ("store_pipeline_bind", "store_pipeline_bind"),
        ("load_pipeline_bind", "load_pipeline_bind"),
        ("scissor_array", "scissor_array"),
        ("depth_bias_array", "depth_bias_array"),
        ("encoder_ptr", "encoder_ptr"),
    )

    # The compact prototype UAPI predates these fields, while unstable-v3 and
    # the Mesa backend carry them. Keep them optional so both front ends use
    # the same generated register recipe.
    OPTIONAL_FROM_DRM = (
        ("multisample_control", "ppp_multisamplectl"),
        ("ppp_control", "ppp_ctrl"),
        ("tib_blocks", "iogpu_unk_49"),
        ("samples", "samples"),
        ("sample_size", "sample_size"),
        ("layers", "layers"),
        ("utile_width", "utile_width"),
        ("utile_height", "utile_height"),
        ("utile_config", "utile_config"),
        ("tile_config", "tile_config"),
        ("occlusion_query_base", "occlusion_query_base"),
        ("depth_dimensions", "isp_zls_pixels"),
        ("depth_buffer", "depth_buffer"),
        ("depth_aux_buffer", "depth_aux_buffer"),
        ("depth_stride", "depth_stride"),
        ("depth_aux_stride", "depth_aux_stride"),
        ("stencil_buffer", "stencil_buffer"),
        ("stencil_aux_buffer", "stencil_aux_buffer"),
        ("stencil_stride", "stencil_stride"),
        ("stencil_aux_stride", "stencil_aux_stride"),
        ("depth_flags", "ds_flags"),
        ("depth_clear_value_bits", "depth_clear_value_bits"),
        ("stencil_clear_value", "stencil_clear_value"),
        ("merge_upper_x_bits", "isp_merge_upper_x"),
        ("merge_upper_y_bits", "isp_merge_upper_y"),
        ("partial_load_pipeline_bind", "partial_reload_pipeline_bind"),
        ("partial_load_pipeline", "partial_reload_pipeline"),
        ("partial_store_pipeline_bind", "partial_store_pipeline_bind"),
        ("partial_store_pipeline", "partial_store_pipeline"),
        ("sampler_array", "sampler_array"),
        ("sampler_count", "sampler_count"),
        ("process_empty_tiles", "process_empty_tiles"),
        ("aux_fb_flags", "aux_fb_flags"),
        ("emit_uapi_fields", "emit_uapi_fields"),
    )

    # Render state the register recipe names and the DRM buffer does not carry.
    EXTERNAL_RENDER_STATE = ("deflake_1", "deflake_2", "deflake_3", "aux_fb", "heapmeta")

    # Submission records the publication path needs and the DRM buffer does not carry.
    EXTERNAL_SUBMISSION_STATE = (
        "shared", "pools", "tiling_optional", "fragment_optional")

    def __init__(self, **fields):
        for name, value in fields.items():
            setattr(self, name, value)


def command_buffer_from_drm(drm, pipeline_base=0, **supplied):
    """Adapt a DRM command buffer into one this backend can build from.

    Two of the differences matter and are handled here. The pipeline fields are offsets from the
    context's pipeline base. Unlike the earlier-generation renderer, the G17P
    register recipe writes the aligned program address unchanged. The tiler
    stream arrives as an address, ``encoder_ptr``, because userspace wrote it;
    this backend passes it through rather than generating one.

    Everything the DRM buffer does not carry must be supplied by name. Refusing here rather than
    defaulting to zero is deliberate: a zero deflake address or a missing record pool publishes a
    structurally valid submission that draws nothing, which is the failure this project has
    repeatedly mistaken for success.
    """
    fields = {name: getattr(drm, drm_name)
              for name, drm_name in G17PCommandBuffer.FROM_DRM}
    for name, drm_name in G17PCommandBuffer.OPTIONAL_FROM_DRM:
        if hasattr(drm, drm_name):
            fields[name] = getattr(drm, drm_name)
    if "samples" in fields and "utile_config" not in fields:
        sample_bits = {1: 0, 2: 1, 4: 2}
        samples = fields.pop("samples")
        if samples not in sample_bits:
            raise G17PUnsupported(
                "G17P sample count must be 1, 2, or 4; got %r" % samples)
        fields["utile_config"] = 0xa000 | sample_bits[samples]
    fields["load_pipeline_bind"] = (
        G17P_LOAD_PIPELINE_BIND_PREFIX | fields["load_pipeline_bind"])
    pipeline_base = getattr(drm, "usc_exec_base", pipeline_base)
    for name in ("store_pipeline", "load_pipeline"):
        fields[name] = pipeline_base + getattr(drm, name)
    if "partial_load_pipeline_bind" in fields:
        fields["partial_load_pipeline_bind"] = (
            G17P_LOAD_PIPELINE_BIND_PREFIX
            | fields["partial_load_pipeline_bind"])
    for name, drm_name in (
            ("partial_load_pipeline", "partial_reload_pipeline"),
            ("partial_store_pipeline", "partial_store_pipeline")):
        value = getattr(drm, drm_name, 0)
        fields[name] = pipeline_base + value if value else 0

    required = (G17PCommandBuffer.EXTERNAL_RENDER_STATE
                + G17PCommandBuffer.EXTERNAL_SUBMISSION_STATE)
    missing = [name for name in required if name not in supplied]
    if missing:
        raise G17PUnsupported(
            "a DRM command buffer does not carry %s, and this backend does not yet derive "
            "them; supply them to command_buffer_from_drm" % ", ".join(missing))

    fields.update(supplied)
    return G17PCommandBuffer(**fields)


class G17PShimObject:
    """One buffer, at a device address, with the host mapping the front end writes through.

    Named ``_addr`` and ``_map`` because that is what ``shim.py`` reads off the objects the
    earlier generations' allocator returns.
    """

    def __init__(self, space, addr, pa, size, name, mapping=None,
                 allocator=None, recyclable=False):
        self.space = space
        self._addr = addr
        self._pa = pa
        self._size = size
        self._name = name
        self._map = None
        self._memfd_offset = None
        self._pushed = False
        self.val = None
        self._mapping = mapping
        self._allocator = allocator
        self._recyclable = bool(recyclable)
        self._destroyed = False

    def push(self, flush=False):
        """Copy explicit bytes or the host mapping into device memory."""
        if self._destroyed:
            raise RuntimeError("%s has been destroyed" % self._name)
        if isinstance(flush, (bytes, bytearray, memoryview)):
            data = bytes(flush)
            if len(data) > self._size:
                raise ValueError(
                    "%s payload is %#x bytes for a %#x-byte object"
                    % (self._name, len(data), self._size)
                )
        elif self._map is not None:
            data = bytes(self._map[:self._size])
        else:
            return self
        self.space.write(self._pa, data)
        self._pushed = True
        return self

    def pull(self):
        """Read device memory back into the host mapping."""
        if self._destroyed:
            raise RuntimeError("%s has been destroyed" % self._name)
        data = self.space.read(self._pa, self._size)
        if self._map is not None:
            self._map[:len(data)] = data
        return data

    def free(self):
        if self._destroyed:
            return
        if self._mapping is None:
            raise RuntimeError("%s has no owned UAT mapping" % self._name)
        self.space.unmap(self._mapping)
        if self._allocator is not None:
            self._allocator.release(self)
        self._map = None
        self.val = None
        self._destroyed = True

    def __repr__(self):
        state = " destroyed" if self._destroyed else ""
        return "<G17PShimObject %s @ %#x (%#x bytes)%s>" % (
            self._name, self._addr, self._size, state)


class G17PShimAllocator:
    """``new(size, name=..., track=...)``, which is the allocator call ``shim.py`` makes."""

    def __init__(self, space, label, base_va=None, max_va=None):
        self.space = space
        self.label = label
        self.next_va = base_va
        self.max_va = max_va
        self.objects = []
        self.free_ranges = []

    def _take_free_range(self, size):
        for index, (addr, span) in enumerate(self.free_ranges):
            if self.max_va is not None and addr + size > self.max_va:
                continue
            if span < size:
                continue
            if span == size:
                del self.free_ranges[index]
            else:
                self.free_ranges[index] = (addr + size, span - size)
            return addr
        return None

    def _return_free_range(self, addr, size):
        self.free_ranges.append((addr, size))
        self.free_ranges.sort()
        merged = []
        for range_addr, range_size in self.free_ranges:
            if merged and merged[-1][0] + merged[-1][1] == range_addr:
                old_addr, old_size = merged[-1]
                merged[-1] = (old_addr, old_size + range_size)
            else:
                merged.append((range_addr, range_size))
        self.free_ranges = merged

    def release(self, obj):
        if obj in self.objects:
            self.objects.remove(obj)
        if not obj._recyclable:
            return
        mapping = obj._mapping
        addr = int(mapping.get("map_va", mapping["va"]))
        size = int(mapping.get("map_size", mapping["size"]))
        self._return_free_range(addr, size)

    def new(self, size, name=None, track=True, **kwargs):
        alloc_size = (size + 0x3fff) & ~0x3fff
        if self.next_va is None:
            addr, pa = self.space.alloc(size, name or self.label)
        else:
            addr = self._take_free_range(alloc_size)
            from_free_range = addr is not None
            next_va = None
            if addr is None:
                addr = (self.next_va + 0x3fff) & ~0x3fff
                next_va = addr + alloc_size
                if self.max_va is not None and next_va > self.max_va:
                    raise MemoryError(
                        "%s exhausted its DVA range: %#x bytes at %#x exceeds %#x" %
                        (self.label, alloc_size, addr, self.max_va))
            try:
                addr, pa = self.space.alloc_at(
                    addr, size, name or self.label, **kwargs)
            except Exception:
                if from_free_range:
                    self._return_free_range(addr, alloc_size)
                raise
            if next_va is not None:
                self.next_va = next_va
        obj = G17PShimObject(
            self.space, addr, pa, size, name or self.label,
            mapping=self.space.objects[-1], allocator=self,
            recyclable=(self.next_va is not None))
        self.objects.append(obj)
        return obj

    def new_at(self, addr, size, name=None, track=True, **flags):
        addr, pa = self.space.alloc_at(
            addr, size, name or self.label, **flags
        )
        obj = G17PShimObject(
            self.space, addr, pa, size, name or self.label,
            mapping=self.space.objects[-1], allocator=self
        )
        self.objects.append(obj)
        return obj


class G17PShimContext:
    """The context object ``shim.py`` reaches through: two allocators and a pipeline base."""

    def __init__(self, space):
        self.space = space
        vm_offset = space.va - SHIM_BASE_VA
        self.pipeline_base = G17P_PIPELINE_BASE + vm_offset
        self.gobj = G17PShimAllocator(
            space, "shim-gobj", space.va, self.pipeline_base)
        self.pobj = G17PShimAllocator(
            space, "shim-pobj", G17P_PIPELINE_START + vm_offset,
            G17P_USER_VA_END)


def grid_index_for(channel_name):
    """The queue's index on the queue grid, from its channel name.

    ``(pair << 2) | kind``. The grid index reaches firmware in queue and event records. It is
    independent of the channel-ring transport selected by a work doorbell: native grids 2/3 can
    be carried over the TA_0/3D_0 rings and notified on channel zero.
    """
    kind, _, pair = channel_name.partition("_")
    order = {"TA": 0, "3D": 1, "CL": 2}
    if kind not in order or not pair.isdigit():
        return 0
    return (int(pair) << 2) | order[kind]


def grid_index_from_queue_address(queue_addr, fallback=0):
    """Derive an observed queue-grid index from the fixed queue array.

    Channel names identify transport rings, not queue-grid slots.  Native CL_0
    traffic, for example, uses grid 10.  Host-created queues outside the fixed
    array retain the caller's fallback index.
    """
    from . import g17p

    base = 0xFFFFFC20C0000000
    offset = int(queue_addr) - base
    if (0 <= offset < 0x4000 and
            offset % g17p.QUEUE_RECORD_STRIDE == 0):
        return offset // g17p.QUEUE_RECORD_STRIDE
    return int(fallback)


def work_doorbell_channel(channel_pair):
    """Return the TA transport channel for a multiplexed work-channel pair."""
    return int(channel_pair) << 2


def uncompressed_twiddled_size(width, height, bytes_per_pixel=4):
    """Bytes occupied by a 64x64 Morton-tiled, uncompressed surface."""
    if not 0 < width <= 0x4000 or not 0 < height <= 0x4000:
        raise ValueError("G17P target dimensions must fit in 14 bits")
    columns = (width + 63) // 64
    rows = (height + 63) // 64
    return columns * rows * 64 * 64 * bytes_per_pixel


def build_linear_bgra8_target_descriptor(target, width, height, kind):
    """Build one complete uncompressed linear BGRA8 texture/PBE record."""
    if target & 0xf:
        raise ValueError("a G17P target address must be 16-byte aligned")
    if not 0 < width <= 0x4000 or not 0 < height <= 0x4000:
        raise ValueError("G17P target dimensions must fit in 14 bits")

    encoded = target >> 4
    width_minus_one = width - 1
    height_minus_one = height - 1
    stride = (width * 4 + 0xff) & ~0xff
    if kind == "texture":
        words = (
            0x060a0a02 | ((width_minus_one & 0xf) << 28),
            ((width_minus_one >> 4) & 0x3ff)
            | ((height_minus_one & 0x3fff) << 10),
            encoded & 0xffffffff,
            (((stride // 16) - 1) << 14) | ((encoded >> 32) & 0xfff),
            0, 0, 0, 0,
        )
    elif kind == "pbe":
        words = (
            0x00c60a02 | ((width_minus_one & 0xff) << 24),
            ((width_minus_one >> 8) & 0x3f)
            | ((height_minus_one & 0x3fff) << 6),
            encoded & 0xffffffff,
            (((stride // 16) - 1) << 12) | ((encoded >> 32) & 0xfff),
            0, 0, 0, 0,
        )
    else:
        raise ValueError("unknown G17P target descriptor kind %r" % kind)
    return words, stride


def patch_uncompressed_target_descriptor(words, target, width, height, kind):
    """Rebase one retained target record and select raw twiddled storage."""
    if len(words) != 8:
        raise ValueError("a G17P target descriptor is eight words")
    if target & 0xf:
        raise ValueError("a G17P target address must be 16-byte aligned")
    if not 0 < width <= 0x4000 or not 0 < height <= 0x4000:
        raise ValueError("G17P target dimensions must fit in 14 bits")

    words = list(words)
    width_minus_one = width - 1
    height_minus_one = height - 1
    if kind == "texture":
        words[0] = ((words[0] & 0x0fffffff)
                    | ((width_minus_one & 0xf) << 28))
        words[1] = ((words[1] & ~0x00ffffff)
                    | ((width_minus_one >> 4) & 0x3ff)
                    | ((height_minus_one & 0x3fff) << 10))
    elif kind == "pbe":
        words[0] = ((words[0] & 0x00ffffff)
                    | ((width_minus_one & 0xff) << 24))
        words[1] = ((words[1] & ~0x000fffff)
                    | ((width_minus_one >> 8) & 0x3f)
                    | ((height_minus_one & 0x3fff) << 6))
    else:
        raise ValueError("unknown G17P target descriptor kind %r" % kind)

    encoded = target >> 4
    words[1] &= ~(1 << 27)
    words[2] = encoded & 0xffffffff
    words[3] = ((words[3] & ~((1 << 31) | 0xfff))
                | ((encoded >> 32) & 0xfff))
    words[4] = 0
    words[5] &= ~0xfff
    return tuple(words)


def build_raw_twiddled_target_descriptor(target, width, height, kind):
    """Build the hardware-proven raw-twiddled target record explicitly."""
    try:
        template = G17P_RAW_TWIDDLED_TEMPLATES[kind]
    except KeyError:
        raise ValueError("unknown G17P target descriptor kind %r" % kind) from None
    return patch_uncompressed_target_descriptor(
        template, target, width, height, kind)


def build_raw_twiddled_attachment_page(base, target, width, height):
    """Build the verified single-BGRA8 LOAD/RENDER/STORE attachment object."""
    if base & 0x3fff:
        raise ValueError("G17P attachment page must be 16 KiB aligned")
    page = bytearray(0x4000)

    for offset, relative in G17P_ATTACHMENT_POINTERS.items():
        struct.pack_into("<Q", page, offset, base + relative)
    for offset, value in G17P_ATTACHMENT_BGRA8_STATE.items():
        struct.pack_into("<I", page, offset, value)
    for offset, kind in ((0x20, "texture"), (0x320, "texture"),
                         (0x620, "pbe"), (0x8e0, "pbe")):
        words = build_raw_twiddled_target_descriptor(
            target, width, height, kind)
        struct.pack_into("<8I", page, offset, *words)

    # Prevent an accidental opaque pointer from entering the constant state.
    expected = {offset: base + relative
                for offset, relative in G17P_ATTACHMENT_POINTERS.items()}
    for offset in range(0, 0xc00, 8):
        value = struct.unpack_from("<Q", page, offset)[0]
        if base <= value < base + 0x4000 and expected.get(offset) != value:
            raise AssertionError(
                "unmodeled attachment pointer %#x at +%#x" % (value, offset))
    return bytes(page)


def build_shader_resource_root_page(code_base=0x10000000000,
                                    uniform_base=0x10001bc0000):
    """Build the pointer-bearing root over compiler code and uniform payloads."""
    if code_base & 0x3fff or uniform_base & 0x3fff:
        raise ValueError("G17P shader resource BOs must be 16 KiB aligned")
    page = bytearray(0x4000)
    for offset, value in G17P_SHADER_RESOURCE_ROOT_STATE.items():
        struct.pack_into("<I", page, offset, value)
    for offset, relative in G17P_SHADER_RESOURCE_CODE_OFFSETS.items():
        struct.pack_into("<Q", page, offset, code_base + relative)
    struct.pack_into(
        "<Q", page, G17P_SHADER_RESOURCE_UNIFORM_OFFSET,
        uniform_base + G17P_SHADER_RESOURCE_UNIFORM_PAYLOAD_OFFSET)
    return bytes(page)


def build_uniform_payload_page(width=2408, height=1506):
    """Build the scalar uniform payload with dimensions supplied by the render."""
    if width <= 0 or height <= 0:
        raise ValueError("G17P uniform dimensions must be positive")
    page = bytearray(0x4000)
    for offset, value in G17P_UNIFORM_SCALARS.items():
        struct.pack_into("<I", page, offset, value)
    for offset in (0x170, 0x1a0):
        struct.pack_into("<f", page, offset, float(width))
    for offset in (0x1a4, 0x1d4):
        struct.pack_into("<f", page, offset, float(height))
    return bytes(page)


class G17PShimBackend:
    """The G17P equivalent of the object ``DRMAsahiShim`` builds in ``init``."""

    def __init__(self, u, initdata_addr, doorbell, context=SHIM_CONTEXT, base_va=SHIM_BASE_VA,
                 adopt=False, firmware_root=None, control_done=None,
                 event_pump=None, runtime_pair_register=None,
                 runtime_submission_announce=None,
                 retained_extent=None, bound_submission=None,
                 secondary_initdata_addr=None,
                 firmware_high_root=None):
        from .g17p_backend import G17PChannels, G17PSubmitter
        from .g17p_device import G17PAddressSpace
        from .g17p_sync import G17PFenceTracker

        self.u = u
        self.firmware_root = firmware_root
        self.space = G17PAddressSpace(u, context, base_va)
        if adopt:
            # Reading a running firmware's state has to go through the tables that firmware is
            # using, not the fresh ones this process just built, and this happens before anything
            # is read: the channel table below is the first read there is.
            adopted = self.space.adopt_live_tables()
            if adopted is not None:
                # Remember the upper root as it was adopted. Allocating later re-initialises the
                # UAT and moves ttbr1_base, so reading it at use time sends firmware reads to a
                # root that no longer describes firmware's address space.
                # A split native topology may deliberately install an empty
                # upper root in the hardware context slot while retaining the
                # populated firmware root off-table. Its in-process bootstrap
                # knows that root and supplies it explicitly.
                self.firmware_high_root = (
                    int(firmware_high_root)
                    if firmware_high_root is not None else adopted[1])
            if adopted is None:
                raise G17PUnsupported(
                    "context %d has no translation root in the hardware context table, so no "
                    "firmware has been started with these tables" % context)
        self.ctx = G17PShimContext(self.space)
        self.initdata_addr = initdata_addr
        self.channels = G17PChannels(self._read_dva, initdata_addr)
        self.secondary_initdata_addr = secondary_initdata_addr
        self.secondary_channels = (
            G17PChannels(self._read_dva, secondary_initdata_addr)
            if secondary_initdata_addr else None)
        self.ack_report_channels = (
            os.getenv("G17P_ACK_REPORT_CHANNELS", "1") != "0")
        if not self.ack_report_channels:
            print(
                "G17P experiment: firmware report-channel acknowledgements "
                "disabled",
                flush=True,
            )
        self.submitter = G17PSubmitter(self._read_dva, self._write_dva, doorbell, self.channels)
        self.fence_tracker = G17PFenceTracker()
        self.control_done = control_done
        self.event_pump = event_pump
        self.runtime_pair_register = runtime_pair_register
        self.runtime_submission_announce = runtime_submission_announce
        # Experiments and the eventual render translator can publish a
        # command-specific device-control transition after every object is
        # built but before either outer work producer becomes visible.
        # A targeted experiment may reveal the fragment producer, run a
        # synchronous control-plane transition, and then reveal tiling. The
        # callback is consumed by exactly one paired publication.
        self.split_pair_publication_hook = None
        self.split_pair_publication_order = ("fragment", "tiling")
        self.clean_dva_writes = os.getenv("G17P_CLEAN_DVA_WRITES") == "1"
        self.runtime_pair_registered = False
        self.runtime_submission_announced = set()
        self.builders = {}
        self.paired_builder = None
        self.paired_builders = {}
        # Queue pairs are multiplexed over a work-channel pair. Native TA_0/3D_0
        # traffic alternates queue grids 0/1 and 2/3 on the same two channel rings.
        self.muxed_queue_pairs = {}
        self.muxed_queue_pointer_sets = {}
        self.muxed_queue_context_pages = {}
        self.destroyed_muxed_queue_pairs = set()
        self.muxed_queue_pair_tombstones = {}
        self.muxed_queue_pair_generations = {}
        self.queue_pair_submissions = {}
        self.queue_pair_priorities = {}
        # The queue ring and descriptor/resource families have independent
        # positions. Native opening traffic keeps appending to grid 0/1 while
        # alternating the pair-0 and pair-1 descriptor namespaces; each
        # descriptor namespace advances only when it is selected.
        self.descriptor_pair_submissions = {}
        # A runtime graph switch can restart a descriptor/resource family while
        # retaining the already-published queue ring.
        self.pair_graph_item_bases = {}
        # Resource/PB lifetime can also restart independently of a descriptor
        # array position.  The partial replay's first newly published command
        # is descriptor item one on an empty transport but resource item zero.
        self.pair_resource_submissions = {}
        # Queue retirement does not make a firmware queue generation reusable.
        # The direct-compute bootstrap consumes fixed grid-4 storage before a
        # partial diagnostic reaches it, so keep a selectable fresh-allocation
        # path which retains the logical grid identity but not the old DVA.
        self.partial_fresh_queue_generation = (
            os.getenv("G17P_PARTIAL_FRESH_QUEUE_GENERATION") == "1")
        # The generated replay's successful fresh queue generation gives the
        # two queue records a private copy of the 0x40-byte queue-context
        # record and one adjacent intrusive job-list head.  Optional work
        # items continue to name the original channel-control record.  Keep
        # that distinction selectable while moving the source path from its
        # older topology, which made all three pointers name shared/fixed
        # objects.
        self.partial_fresh_transport_topology = (
            os.getenv("G17P_PARTIAL_FRESH_TRANSPORT_TOPOLOGY") == "1")
        # A relocation-normalized diff against the executing generated replay
        # leaves only these two live fields in each otherwise-exact queue
        # record.  Keep the captured values behind a discriminator until the
        # host-side lifecycle which derives them is decoded.
        self.partial_replay_queue_live_fields = (
            os.getenv("G17P_PARTIAL_REPLAY_QUEUE_LIVE_FIELDS") == "1")
        # Keep the in-place path selectable while testing it against native
        # captures, which append a fresh three-item group for later work.
        self.reuse_queue_items = os.getenv("G17P_REUSE_QUEUE_ITEMS", "1") != "0"
        self.append_reused_queue_items = (
            os.getenv("G17P_APPEND_REUSED_QUEUE_ITEMS") == "1")
        self.scheduler_node_state = os.getenv("G17P_SCHEDULER_NODE", "1") != "0"
        self.materialize_reserved_scheduler_node = (
            os.getenv("G17P_MATERIALIZE_RESERVED_SCHEDULER_NODE") == "1")
        self.keep_base_descriptor_mirrors = (
            os.getenv("G17P_KEEP_BASE_DESCRIPTOR_MIRRORS") == "1")
        self.tile_heap_marker = os.getenv("G17P_TILE_HEAP_MARKER", "1") != "0"
        self.native_pb_release_previous = (
            os.getenv("G17P_NATIVE_PB_RELEASE_PREVIOUS") == "1")
        # The final-26.6 forced-partial stream gives its opening grid-0/1
        # queues the first scheduler head and channel-control record.  The
        # generic cold-boot image instead seeds those same grid records as the
        # init pair, using the second head/record.  Keep the measured partial
        # ownership profile explicit until it becomes the normal queue-create
        # lifecycle used by the DRM scheduler.
        self.native_partial_opening_queue = (
            os.getenv("G17P_NATIVE_PARTIAL_OPENING_QUEUE") == "1")
        self.native_partial_opening_queue_applied = False
        self.native_shared_inner_sequence = (
            os.getenv("G17P_NATIVE_SHARED_INNER_SEQUENCE") == "1")
        self.native_split_lifecycle_publication = (
            os.getenv("G17P_NATIVE_SPLIT_LIFECYCLE_PUBLICATION") == "1")
        self.native_scheduler_publication = (
            os.getenv("G17P_NATIVE_SCHEDULER_PUBLICATION") == "1")
        self.native_leaf_lifecycle = (
            os.getenv("G17P_NATIVE_LEAF_LIFECYCLE") == "1")
        self.native_leaf_publication = (
            os.getenv("G17P_NATIVE_LEAF_PUBLICATION") == "1")
        self.patch_pair1_pool_b_completion = (
            os.getenv("G17P_PATCH_PAIR1_POOL_B_COMPLETION") == "1")
        self.native_status_publication = (
            os.getenv("G17P_NATIVE_STATUS_PUBLICATION") == "1")
        self.native_primary_publication = (
            os.getenv("G17P_NATIVE_PRIMARY_PUBLICATION") == "1")
        self.advance_tilemap_block = os.getenv("G17P_ADVANCE_TILEMAP", "1") != "0"
        self.pair_resource_namespace = (
            os.getenv("G17P_PAIR_RESOURCE_NAMESPACE") == "1")
        self.pair_resource_namespace_after_first = (
            os.getenv("G17P_PAIR_RESOURCE_NAMESPACE_AFTER_FIRST") == "1")
        self.native_fragment_2174 = (
            os.getenv("G17P_NATIVE_FRAGMENT_2174") == "1")
        self.native_b2_scalars = os.getenv("G17P_NATIVE_B2_SCALARS") == "1"
        self.native_b2_full_descriptor_shape = (
            os.getenv("G17P_NATIVE_B2_FULL_DESCRIPTOR_SHAPE") == "1")
        self.native_queue_completion_counters = (
            os.getenv("G17P_NATIVE_QUEUE_COMPLETION_COUNTERS") == "1")
        self.native_b2_control_state = (
            os.getenv("G17P_NATIVE_B2_CONTROL_STATE") == "1")
        self.runtime_current_job_records = (
            os.getenv("G17P_RUNTIME_CURRENT_JOB_RECORDS") == "1")
        self.lag_current_job_records = (
            os.getenv("G17P_LAG_CURRENT_JOB_RECORDS") == "1")
        self.previous_current_job_record = None
        self.group_identity_fields = os.getenv("G17P_GROUP_IDENTITY", "1") != "0"
        self.own_pair_dispatch_count = os.getenv("G17P_PAIR_DISPATCH_COUNT", "1") != "0"
        self.last_published_pair = None
        self.next_scheduler_node = 0
        self.reusable_queue_items = {}
        self.render_objects = {}
        self.execution_contexts = {
            context: {
                "space": self.space,
                "ctx": self.ctx,
                "render_objects": self.render_objects,
            }
        }
        self.destroyed_execution_contexts = {}
        self.primary_execution_context = context
        self.active_execution_context = context
        # Native traffic on this part uses one firmware-visible render context.
        # Keep independent DRM-file VMs in the host, and optionally switch their
        # roots through that admitted context while submissions are serialized.
        self.logical_vm_switch = os.getenv("G17P_LOGICAL_VM_SWITCH") == "1"
        self.mirror_registered_vm = os.getenv("G17P_MIRROR_REGISTERED_VM") == "1"
        self.alternate_queue_pairs = os.getenv("G17P_ALTERNATE_QUEUE_PAIRS") == "1"
        self.forced_queue_pair = None
        self.forced_channel_pair = None
        self.forced_descriptor_pair = None
        self.forced_descriptor_context = None
        self.forced_queue_context = None
        self.forced_optional_ordinal_base = None
        self.partial_render_pair2_profile = False
        self.forced_scheduler_node = None
        self.forced_pool_record_indices = None
        self.allow_quiesced_primary_index_alias_rebind = False
        self.omit_optional_item = False
        self.native_context2_primary_channel = (
            os.getenv("G17P_NATIVE_CONTEXT2_PRIMARY_CHANNEL") == "1")
        self.steady_initial_pair = os.getenv("G17P_STEADY_INITIAL_PAIR") == "1"
        self.pair0_after_b1 = os.getenv("G17P_PAIR0_AFTER_B1") == "1"
        # Native startup moves from the initial pair to the created pair and then sends several
        # consecutive groups to that created pair. Keep strict alternation as a diagnostic, but
        # expose the measured steady-pair policy independently.
        self.steady_created_pair = os.getenv("G17P_STEADY_CREATED_PAIR") == "1"
        self.register_runtime_pair = os.getenv("G17P_RUNTIME_PAIR_REGISTRATION") == "1"
        self.defer_pair1_graph_until_registration = (
            os.getenv("G17P_DEFER_PAIR1_GRAPH_UNTIL_REGISTRATION") == "1")
        self.reset_pair_control = os.getenv("G17P_RESET_PAIR_CONTROL") == "1"
        self.patch_native_prior_control = (
            os.getenv("G17P_PATCH_NATIVE_PRIOR_CONTROL") == "1")
        self.share_bound_submission_state = (
            os.getenv("G17P_SHARE_BOUND_SUBMISSION_STATE") == "1")
        self.share_bound_record_pools = (
            os.getenv("G17P_SHARE_BOUND_RECORD_POOLS") == "1")
        self.pool_b_logical_bias = 0
        self.reset_render_state = os.getenv("G17P_RESET_RENDER_STATE") == "1"
        self.wait_channel_completion = (
            os.getenv("G17P_WAIT_CHANNEL_COMPLETION") == "1")
        self.publish_dsb = os.getenv("G17P_PUBLISH_DSB") == "1"
        self.first_control_done_count = int(
            os.getenv("G17P_FIRST_CONTROL_DONE_COUNT", "2"), 0)
        if self.first_control_done_count < 0:
            raise ValueError("G17P_FIRST_CONTROL_DONE_COUNT must be non-negative")
        self.control_done_count = int(
            os.getenv("G17P_CONTROL_DONE_COUNT", "1"), 0)
        if self.control_done_count < 0:
            raise ValueError("G17P_CONTROL_DONE_COUNT must be non-negative")
        self.pipeline_first_pair = os.getenv("G17P_PIPELINE_FIRST_PAIR") == "1"
        self.prefill_second_pair = os.getenv("G17P_PREFILL_SECOND_PAIR") == "1"
        self.deferred_first_submission = None
        self.prefilled_second_submission = None
        self.pre_notify_hook = None
        self.registered_context_slots = None
        self.group_number = 0
        self.runtime_prepared = False
        self.render_context_base = G17P_RENDER_CONTEXT_BASE
        self.render_layout = G17P_RENDER_LAYOUT
        self.retained_extent = {
            (int(address, 0) if isinstance(address, str) else int(address)):
            (int(pa, 0) if isinstance(pa, str) else int(pa))
            for address, pa in (retained_extent or {}).items()
        }
        self.bound_submission = bound_submission or {}
        self.bound_color_attachment = None

    def submission_queue_pair(self):
        """Choose the queue pair for the next global submission."""
        if self.forced_queue_pair is not None:
            return int(self.forced_queue_pair)
        if getattr(self, "steady_initial_pair", False):
            return 0
        if getattr(self, "pair0_after_b1", False):
            return 1 if self.group_number == 1 else 0
        if getattr(self, "steady_created_pair", False):
            return 0 if self.group_number == 0 else 1
        if getattr(self, "alternate_queue_pairs", False):
            return self.group_number & 1
        return None

    # The channel table is addressed by device address, so reads and writes for it go through
    # the address space rather than through a physical address.
    def _read_dva(self, dva, size):
        # Firmware's own addresses are in the high half and are reached by walking its root, which
        # is not in the hardware context table. Objects this backend allocates are in its own
        # context and must go the ordinary way; routing those through the firmware root looks for
        # them where they were never mapped.
        if self.firmware_root == "high" and dva >= 0xffff000000000000:
            root = getattr(self, "firmware_high_root", None) or self.space.uat.ttbr1_base
            # Firmware's addresses are in the high half and resolve through the upper root, which
            # the adopt step read out of the live hardware context table.
            return self.space.uat.ioread_root(root, dva, size)
        if self.firmware_root and self.firmware_root != "high":
            # Firmware's context is not in the hardware context table, by the same property that
            # makes a post-start submission work, so its state is read by walking its root.
            return self.space.uat.ioread_root(self.firmware_root, dva, size)
        return self.space.uat.ioread(self.space.context, dva, size)

    def _write_dva(self, dva, data):
        # Firmware's own addresses are in the high half and are reached by walking its root, which
        # is not in the hardware context table. Objects this backend allocates are in its own
        # context and must go the ordinary way; routing those through the firmware root looks for
        # them where they were never mapped.
        if self.firmware_root == "high" and dva >= 0xffff000000000000:
            root = getattr(self, "firmware_high_root", None) or self.space.uat.ttbr1_base
            self.space.uat.iowrite_root(root, dva, data)
            ranges = self.space.uat.iotranslate_root(root, dva, len(data))
        else:
            self.space.uat.iowrite(self.space.context, dva, data)
            ranges = self.space.uat.iotranslate(
                self.space.context, dva, len(data))
        if self.clean_dva_writes:
            remaining = len(data)
            for pa, size in ranges:
                if pa is None:
                    raise RuntimeError("unmapped DVA while cleaning %#x" % dva)
                length = min(size, remaining)
                self.u.proxy.dc_civac(pa, length)
                remaining -= length
                if not remaining:
                    break

    def _retained_ranges(self, dva, size):
        """Resolve a retained render range through the cold boot's physical extent."""
        page_size = 0x4000
        done = 0
        while done < size:
            current = dva + done
            page = current & ~(page_size - 1)
            offset = current - page
            length = min(page_size - offset, size - done)
            pa = self.retained_extent.get(page)
            if pa is None:
                raise G17PUnsupported(
                    "the cold-boot artifact does not record retained render page %#x" % page)
            yield pa, offset, length
            done += length

    def _read_retained(self, dva, size):
        data = []
        for pa, offset, length in self._retained_ranges(dva, size):
            self.u.proxy.dc_civac(pa, 0x4000)
            data.append(bytes(self.u.iface.readmem(pa + offset, length)))
        return b"".join(data)

    def _write_retained(self, dva, data):
        data = bytes(data)
        written = 0
        for pa, offset, length in self._retained_ranges(dva, len(data)):
            self.u.iface.writemem(pa + offset, data[written:written + length])
            self.u.proxy.dc_civac(pa, 0x4000)
            written += length

    def bind_color_attachment(self, target, size, width, height):
        """Build LOAD/RENDER/STORE state for one raw-twiddled color BO."""
        if not self.retained_extent:
            raise G17PUnsupported(
                "G17P color attachments require the retained render extent from boot.json")
        required = uncompressed_twiddled_size(width, height)
        if size < required:
            raise G17PUnsupported(
                "G17P color attachment at %#x is %#x bytes; a %dx%d raw-twiddled "
                "surface needs %#x" % (target, size, width, height, required))

        for address, kind in G17P_RETAINED_TARGET_DESCRIPTORS:
            words = build_raw_twiddled_target_descriptor(
                target, width, height, kind)
            self._write_retained(address, struct.pack("<8I", *words))
            check = struct.unpack("<8I", self._read_retained(address, 32))
            if check != words:
                raise RuntimeError(
                    "generated %s target record at %#x did not read back" %
                    (kind, address))

        old_target = ((self.bound_color_attachment or {}).get("target")
                      or G17P_RETAINED_TARGET)
        self.bound_color_attachment = {
            "target": target,
            "size": size,
            "width": width,
            "height": height,
            "required": required,
        }
        print("G17P color attachment: %#x -> %#x, %dx%d raw twiddled "
              "(%#x bytes), "
              "five records" %
              (old_target, target, width, height, required), flush=True)
        return self.bound_color_attachment

    def bind(self):
        self.space.bind()

    def create_execution_context(self, context):
        """Create an independent low-half UAT context for one DRM file."""
        context = int(context)
        if context in self.destroyed_execution_contexts:
            raise G17PUnsupported(
                "execution context %d was destroyed" % context)
        existing = self.execution_contexts.get(context)
        if existing is not None:
            return existing
        source = self.execution_contexts[self.primary_execution_context]["space"]
        base_va = SHIM_BASE_VA
        if self.logical_vm_switch:
            stride = int(os.getenv("G17P_LOGICAL_VM_STRIDE", "0x100000000"), 0)
            base_va += (context - self.primary_execution_context) * stride
        space = source.clone_for_context(context, base_va)
        if self.mirror_registered_vm:
            space.mirror_space = source
        render_objects = (
            self.execution_contexts[self.primary_execution_context]["render_objects"]
            if self.mirror_registered_vm else {}
        )
        state = {
            "space": space,
            "ctx": G17PShimContext(space),
            "render_objects": render_objects,
        }
        self.execution_contexts[context] = state
        return state

    def destroy_execution_context(self, context):
        """Unbind an idle non-primary UAT context and reject stale handles."""
        context = int(context)
        if context == self.primary_execution_context:
            raise G17PUnsupported(
                "the firmware's primary execution context requires device teardown")
        if context in self.destroyed_execution_contexts:
            return self.destroyed_execution_contexts[context]
        state = self.execution_contexts.get(context)
        if state is None:
            raise KeyError("execution context %d does not exist" % context)

        pending_fences = self.fence_tracker.outstanding(context_id=context)
        if pending_fences:
            raise RuntimeError(
                "execution context %d still owns %d pending submission fence(s)" %
                (context, len(pending_fences)))

        last = getattr(self, "last_submission", None)
        if (last is not None and last.get("context_id") == context
                and not self.pair_queue_completed(last)):
            raise RuntimeError(
                "execution context %d still has pending queue work" % context)

        live = []
        for allocator_name in ("gobj", "pobj"):
            allocator = getattr(state["ctx"], allocator_name)
            live.extend(
                obj for obj in allocator.objects
                if not getattr(obj, "_destroyed", False))
        if live or state["space"].objects:
            names = [getattr(obj, "_name", repr(obj)) for obj in live]
            names.extend(mapping["name"] for mapping in state["space"].objects)
            raise RuntimeError(
                "execution context %d still owns mappings: %s" %
                (context, ", ".join(dict.fromkeys(names))))

        if self.active_execution_context == context:
            self.activate_execution_context(self.primary_execution_context)

        space = state["space"]
        roots = (space.uat.ttbr0_base, space.uat.ttbr1_base)
        space.uat.set_l0(context, 0, 0, context)
        space.uat.set_l0(context, 1, 0, context)
        space.uat.flush_dirty()
        space.uat.invalidate_cache()
        self.u.inst("tlbi aside1os, x0", context << 48)
        self.u.inst("dsb sy")

        checks = (
            space.uat.iotranslate(context, 0, space.uat.PAGE_SIZE),
            space.uat.iotranslate(
                context, state["ctx"].pipeline_base, space.uat.PAGE_SIZE),
        )
        if any(any(pa is not None for pa, _span in result)
               for result in checks):
            raise RuntimeError(
                "destroyed execution context %d still translates: %r" %
                (context, checks))

        tombstone = {
            "context": context,
            "roots": roots,
            "base_va": space.va,
        }
        del self.execution_contexts[context]
        self.destroyed_execution_contexts[context] = tombstone
        return tombstone

    def release_execution_context_render_objects(self, context):
        """Release driver-owned render objects before unbinding one context."""
        context = int(context)
        state = self.execution_contexts.get(context)
        if state is None:
            raise KeyError("execution context %d does not exist" % context)
        pending_fences = self.fence_tracker.outstanding(context_id=context)
        if pending_fences:
            raise RuntimeError(
                "execution context %d still owns %d pending submission fence(s)" %
                (context, len(pending_fences)))
        last = getattr(self, "last_submission", None)
        if (last is not None and last.get("context_id") == context
                and not self.pair_queue_completed(last)):
            raise RuntimeError(
                "execution context %d still has pending queue work" % context)
        primary_objects = self.execution_contexts[
            self.primary_execution_context]["render_objects"]
        objects = state["render_objects"]
        if objects is primary_objects:
            return 0
        released = 0
        for obj in list(objects.values()):
            if not getattr(obj, "_destroyed", False):
                obj.free()
                released += 1
        objects.clear()
        return released

    def activate_execution_context(self, context):
        """Select the address space used to build and submit the next DRM job."""
        context = int(context)
        state = self.execution_contexts.get(context)
        if state is None:
            state = self.create_execution_context(context)
        self.space = state["space"]
        self.ctx = state["ctx"]
        self.render_objects = state["render_objects"]
        self.active_execution_context = context
        if self.logical_vm_switch and not self.mirror_registered_vm:
            self._switch_registered_context_root(self.space)
        return state

    def _switch_registered_context_root(self, space):
        """Point firmware's admitted render context at one logical DRM VM."""
        from ..hw.uat import TTBR

        registered = self.primary_execution_context
        if self.registered_context_slots is None:
            slots = []
            for slot in range(space.uat.NUM_CONTEXTS):
                base = space.uat.gpu_region + slot * 16
                low = TTBR(self.u.proxy.read64(base))
                if low.VALID and low.ASID == registered:
                    slots.append(slot)
            if not slots:
                raise RuntimeError(
                    "no hardware UAT slot is tagged for registered context %d" %
                    registered)
            self.registered_context_slots = tuple(slots)

        for slot in self.registered_context_slots:
            space.uat.set_l0(slot, 0, space.uat.ttbr0_base, registered)
            space.uat.set_l0(slot, 1, space.uat.ttbr1_base, registered)
        space.uat.flush_dirty()
        space.uat.invalidate_cache()
        self.u.inst("dsb sy")
        self.u.inst("tlbi aside1os, x0", registered << 48)
        self.u.inst("dsb sy")
        print(
            "  switched registered context %d slots %s to logical context %d root %#x" % (
                registered,
                ",".join(str(slot) for slot in self.registered_context_slots),
                space.context,
                space.uat.ttbr0_base,
            ),
            flush=True,
        )

    def queue_for(self, channel_name):
        # The grid index is not zero for every queue: it reaches firmware in the event record's
        # subtype, and a fragment queue publishing with a tiling queue's index leaves the group
        # retiring without drawing. Measured on the first pair, where the tiling queue is 0 and
        # the fragment queue 1. The doorbell separately selects the transport channel pair.
        from .g17p_backend import G17PQueue

        entry = self.channels.by_name(channel_name)
        ring = entry["ring_addr"]
        queue_addr = struct.unpack("<Q", self._read_dva(ring + 8, 8))[0]
        if not queue_addr:
            raise RuntimeError(
                "%s ring %#x has no queue pointer in slot zero" %
                (channel_name, ring))
        fallback = grid_index_for(channel_name)
        return entry, G17PQueue(
            self._read_dva, queue_addr,
            grid_index_from_queue_address(queue_addr, fallback),
        )

    def builder_for(self, kind):
        from .g17p_backend import G17PWorkBuilder

        if kind not in self.builders:
            builder = G17PWorkBuilder(
                lambda size, name: self.space.alloc(size, name)[0],
                lambda addr, data: self._write_dva(addr, data),
                kind=kind,
            )
            self.builders[kind] = builder
        return self.builders[kind]

    QUEUE_RECORD_FIELDS = (
        (0x20, 0xffffffff00000000),
        (0x30, 0xffffffffffff0000),
        (0x38, 0x0000000000000001),
        (0x40, 0xffffffff00000001),
    )

    QUEUE_POINTER_FIELDS = ((0x50, 0xffffffff), (0x60, 0x500))

    # Queue-context objects have a low context-side address and a high
    # firmware-side address. Pairs 1-3 alias both addresses to the same backing;
    # native context 4 proves pair 4 uses distinct zeroed low backing.
    MUX_PAIR_CONTEXTS = {
        1: {
            "tiling": {"low": 0x7000488000, "high": 0xfffffc2000228000},
            "fragment": {"low": 0x70004b0000, "high": 0xfffffc2000250000},
        },
        2: {
            "tiling": {"low": 0x70004d8000, "high": 0xfffffc2000278000},
            "fragment": {"low": 0x7000500000, "high": 0xfffffc20002a0000},
        },
        3: {
            "tiling": {"low": 0x7000528000, "high": 0xfffffc20002c8000},
            "fragment": {"low": 0x7000550000, "high": 0xfffffc20002f0000},
        },
        4: {
            "tiling": {"low": 0x70005f0000, "high": 0xfffffc2000390000},
            "fragment": {"low": 0x7000618000, "high": 0xfffffc20003b8000},
        },
    }
    MUX_PAIR1_CONTEXT_PAGES = 8
    PAIR_RENDER_STATUS_BASES = {
        "tiling": (0x1000078000, 0x1000660000, 0x1000c40000,
                   0x1000078000),
        "fragment": (0x10001a8000, 0x1000788000, 0x1000d68000,
                     0x10001a8000),
    }
    MUX_PAIR1_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000180,
            "pointers": 0xfffffc20000150e0,
            "item_ring": 0xfffffc20c000d0e0,
        },
        "fragment": {
            "queue": 0xfffffc20c0000240,
            "pointers": 0xfffffc2001658000,
            "item_ring": 0xfffffc20c08a8000,
        },
    }
    # The forced-partial lifecycle does not use the ordinary pair-one queue
    # incarnation above.  After 36 grid-0/1 renders, it creates grid 2/3 on
    # TA_2/3D_2.  TA retains the allocator's first pair-one pointer/ring
    # addresses while 3D lands in the later c1668/c08b allocations.  These
    # values come from the synchronized pre-class2 host-write trace, before
    # either queue has published work.
    PARTIAL_PRE_CLASS2_PAIR1_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000180,
            "pointers": 0xfffffc20000150e0,
            "item_ring": 0xfffffc20c000d0e0,
        },
        "fragment": {
            "queue": 0xfffffc20c0000240,
            "pointers": 0xfffffc2001668000,
            "item_ring": 0xfffffc20c08b0000,
        },
    }
    NATIVE_PAIR2_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000300,
            "pointers": 0xfffffc200165a870,
            "item_ring": 0xfffffc20c08aa870,
        },
        "fragment": {
            "queue": 0xfffffc20c00003c0,
            "pointers": 0xfffffc200165d0e0,
            "item_ring": 0xfffffc20c08ad0e0,
        },
    }
    # The forced-partial render is a later incarnation of logical grids 4/5.
    # It reuses the two queue-record addresses above, but replaces their
    # pointer blocks, item rings, scheduler head, UUID, optional control page,
    # and complete PB/submission graph.  Keep this as a named profile: the
    # earlier pair-2 incarnation remains valid evidence for the compute
    # transition and the two lifecycles must not be conflated.
    PARTIAL_PAIR2_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000300,
            "pointers": 0xfffffc200166a870,
            "item_ring": 0xfffffc20c08b2870,
        },
        "fragment": {
            "queue": 0xfffffc20c00003c0,
            "pointers": 0xfffffc200166d0e0,
            "item_ring": 0xfffffc20c08b50e0,
        },
    }
    # Native's first TA_2/3D_2 phase uses queue grids 6/7 and context 2. These
    # are the queue objects observed at that transition; the later CL phase
    # replaces the same queue-grid records with a second incarnation.
    NATIVE_PAIR3_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000480,
            "pointers": 0xfffffc20016a0000,
            "item_ring": 0xfffffc20c0900000,
        },
        "fragment": {
            "queue": 0xfffffc20c0000540,
            "pointers": 0xfffffc20016a2870,
            "item_ring": 0xfffffc20c0902870,
        },
    }
    NATIVE_PAIR4_QUEUES = {
        "tiling": {
            "queue": 0xfffffc20c0000840,
            "pointers": 0xfffffc20016fd0e0,
            "item_ring": 0xfffffc20c09650e0,
        },
        "fragment": {
            "queue": 0xfffffc20c0000900,
            "pointers": 0xfffffc2001748000,
            "item_ring": 0xfffffc20c09c0000,
        },
    }
    NATIVE_PAIR4_JOB_LIST = 0xfffffc2000000060
    NATIVE_PAIR4_CHANNEL_CONTROL = 0xfffffc20c07b8100
    NATIVE_PAIR4_SHARED_CONTROL = 0xfffffc20c0928000
    NATIVE_PAIR4_UUID = 0x197
    NATIVE_PAIR4_SUBMISSION_ORDINAL = 0x93d
    NATIVE_PAIR4_LIFECYCLE_ORDINAL = 0x96f
    NATIVE_PAIR3_JOB_LIST = 0xfffffc2000000030
    NATIVE_PAIR3_CHANNEL_CONTROL = 0xfffffc20c07b8080
    NATIVE_PAIR3_ITEM_RING_SIZE = 0x2870
    NATIVE_PAIR3_UUID = 0x15e
    NATIVE_CONTEXT2_JOB_LIST = 0xfffffc2000000030
    NATIVE_CONTEXT2_CHANNEL_CONTROL = 0xfffffc20c07b8080
    NATIVE_CONTEXT2_ITEM_RING_SIZE = 0x2870
    NATIVE_PAIR2_UUID = 0x148
    NATIVE_PAIR2_SHARED_CONTROL = 0xfffffc20c08c0000
    NATIVE_PAIR3_SHARED_CONTROL = 0xfffffc20c08f8000
    PARTIAL_PAIR2_JOB_LIST = 0xfffffc2000000048
    PARTIAL_PAIR2_CHANNEL_CONTROL = 0xfffffc20c07b80c0
    PARTIAL_PAIR2_SHARED_CONTROL = 0xfffffc20c08d0000
    PARTIAL_PAIR2_SHARED_CONTROL_INNER = 0xfffffc2001688000
    PARTIAL_PAIR2_CONTROL_OPERAND = 0x7000208000
    PARTIAL_PAIR2_UUID = 0x186
    PARTIAL_PAIR2_OPTIONAL_ORDINAL = 0x25
    PARTIAL_PRE_CLASS2_PAIR1_JOB_LIST = 0xfffffc2000000018
    PARTIAL_PRE_CLASS2_PAIR1_CHANNEL_CONTROL = 0xfffffc20c07b8040
    PARTIAL_PRE_CLASS2_PAIR1_UUID = 0x16e
    # Allocation order used by G17PPairedWorkBuilder. These are the complete pair-one graph
    # addresses from the native second-doorbell snapshot. Keep the names in the tuple: a changed
    # builder allocation order must fail loudly instead of silently putting an object in the wrong
    # measured slot.
    MUX_PAIR1_GRAPH = (
        # The native first-to-second-doorbell differential grows these as
        # four and two firmware pages respectively.  The builder currently
        # populates only page zero, but firmware walks and fills the trailing
        # pages while admitting the new queue-resource lifecycle.
        ("submission_primary_index", 0xfffffc20c0888000, 0x10000),
        ("submission_secondary_index", 0xfffffc20c0878000, 0x8000),
        ("submission_pool_a_slots", 0xfffffc20015f8000, 0x4000),
        ("submission_pool_b_slots", 0xfffffc2001620000, 0x4000),
        ("submission_shared_slots", 0xfffffc2001640000, 0x4000),
        ("submission_flag", 0xfffffc2001648000, 0x4000),
        ("record_pool_a", 0xfffffc20c0820100, 0x2300),
        ("record_pool_b", 0xfffffc20c0870080, 0x2780),
        ("descriptor_shared_object", 0xfffffc20c08a0000, 0x88),
        ("descriptor_zero_object", 0xfffffc20c0872800, 0x100),
    )
    MUX_PAIR2_GRAPH = (
        ("submission_primary_index", 0xfffffc20c08e0000, 0x4000),
        ("submission_secondary_index", 0xfffffc20c08d0000, 0x4000),
        ("submission_pool_a_slots", 0xfffffc2001608000, 0x4000),
        ("submission_pool_b_slots", 0xfffffc2001688000, 0x4000),
        ("submission_shared_slots", 0xfffffc2001680000, 0x4000),
        ("submission_flag", 0xfffffc2001690000, 0x4000),
        ("record_pool_a", 0xfffffc20c0830100, 0x2300),
        ("record_pool_b", 0xfffffc20c08c8080, 0x2780),
        ("descriptor_shared_object", 0xfffffc20c08f8000, 0x88),
        ("descriptor_zero_object", 0xfffffc20c08ca800, 0x100),
    )
    PARTIAL_PAIR2_GRAPH = (
        ("submission_primary_index", 0xfffffc20c08f0000, 0x4000),
        ("submission_secondary_index", 0xfffffc20c08e0000, 0x4000),
        ("submission_pool_a_slots", 0xfffffc2001680000, 0x4000),
        ("submission_pool_b_slots", 0xfffffc20016a0000, 0x4000),
        ("submission_shared_slots", 0xfffffc2001698000, 0x4000),
        ("submission_flag", 0xfffffc20016a8000, 0x4000),
        ("record_pool_a", 0xfffffc20c08c8100, 0x2300),
        ("record_pool_b", 0xfffffc20c08d8080, 0x2780),
        ("descriptor_shared_object", 0xfffffc20c0908000, 0x88),
        ("descriptor_zero_object", 0xfffffc20c08da800, 0x100),
    )
    MUX_PAIR3_GRAPH = (
        ("submission_primary_index", 0xfffffc20c0928000, 0x4000),
        ("submission_secondary_index", 0xfffffc20c0918000, 0x4000),
        ("submission_pool_a_slots", 0xfffffc2001688000, 0x4000),
        ("submission_pool_b_slots", 0xfffffc20016b8000, 0x4000),
        ("submission_shared_slots", 0xfffffc20016b0000, 0x4000),
        ("submission_flag", 0xfffffc20016c0000, 0x4000),
        ("record_pool_a", 0xfffffc20c08f0100, 0x2300),
        ("record_pool_b", 0xfffffc20c0910080, 0x2780),
        ("descriptor_shared_object", 0xfffffc20c0940000, 0x88),
        ("descriptor_zero_object", 0xfffffc20c0912800, 0x100),
    )
    # The controlled context-4 render is a later allocation incarnation than
    # the context-2 pair above.  In particular, its optional shared-control
    # object at c0928 is not its primary-index page.  Keeping the two plans
    # separate prevents the pair-4 builder from overwriting that class-4 state
    # with an index array.
    MUX_PAIR4_GRAPH = (
        ("submission_primary_index", 0xfffffc20c09a8000, 0x4000),
        ("submission_secondary_index", 0xfffffc20c0998000, 0x4000),
        ("submission_pool_a_slots", 0xfffffc2001708000, 0x4000),
        ("submission_pool_b_slots", 0xfffffc2001730000, 0x4000),
        ("submission_shared_slots", 0xfffffc2001728000, 0x4000),
        ("submission_flag", 0xfffffc2001738000, 0x4000),
        ("record_pool_a", 0xfffffc20c0970100, 0x2300),
        ("record_pool_b", 0xfffffc20c0938080, 0x2780),
        ("descriptor_shared_object", 0xfffffc20c0940000, 0x88),
        ("descriptor_zero_object", 0xfffffc20c093a800, 0x100),
    )
    # Work-item arrays are shared by both queue pairs and indexed by global
    # publication order. Captured addresses advance 0, 1, 2, ... even when the
    # same pair is used repeatedly. Descriptor pages also have low aliases
    # through which firmware reads the full command body.
    ITEM_ARRAYS = {
        "fragment_optional_item": (0xfffffc20c0600000, 0x180, 0xc0),
        "tiling_optional_item": (0xfffffc20c06000c0, 0x180, 0xc0),
        "fragment_event_item": (0xfffffc20c05e8000, 0x80, 0x400),
        "tiling_event_item": (0xfffffc20c05e8040, 0x80, 0x400),
        "tiling_descriptor": (0xfffffc20c0018000, 0x9c0, 0x9c0),
        "fragment_descriptor": (0xfffffc20c00b0000, 0x2240, 0x2240),
    }
    DESCRIPTOR_LOW_ARRAYS = {
        "tiling_descriptor": 0x7000000000,
        "fragment_descriptor": 0x7000098000,
    }
    CHANNEL_CONTROL_BASE = 0xfffffc20c07b8000
    CHANNEL_CONTROL_STRIDE = 0x40
    CHANNEL_CONTROL_FRESH_WORDS = (
        (0x00, 0x000001000000ffff),
        (0x20, 0x0002000000000000),
        (0x30, 0x00000000ff000000),
    )
    CHANNEL_CONTROL_NATIVE_SECOND_WORDS = (
        (0x48, 0x01dc00005dc00000),
        (0x60, 0x2e02000000000000),
        (0x68, 0x0000036448000002),
    )
    SHARED_CONTROL_NATIVE_FOURTH_WORDS = (
        (0x20, 0x00001ed8000001d8),
        (0x28, 0x00001d0000000000),
    )
    CHANNEL_CONTROL_NATIVE_FOURTH_WORDS = (
        (0x08, 0x005400001f400000),
        (0x20, 0xbc02000000000000),
        (0x28, 0x000000ad1000000d),
        (0x48, 0x021400005dc00000),
        (0x60, 0x6f02000000000000),
        (0x68, 0x000003f466000004),
    )

    def _patch_native_prior_channel_state(self):
        """Install the three prior-pair words measured before native work two."""
        before = self._read_dva(self.CHANNEL_CONTROL_BASE, 0x80)
        for offset, value in self.CHANNEL_CONTROL_NATIVE_SECOND_WORDS:
            self._write_dva(
                self.CHANNEL_CONTROL_BASE + offset,
                struct.pack("<Q", value))
        after = self._read_dva(self.CHANNEL_CONTROL_BASE, 0x80)
        changed = [
            offset for offset, _value in self.CHANNEL_CONTROL_NATIVE_SECOND_WORDS
            if before[offset:offset + 8] != after[offset:offset + 8]
        ]
        print(
            "  patched native prior channel state at qwords %s" %
            ",".join("%#x" % offset for offset in changed),
            flush=True,
        )

    def _patch_native_b2_control_state(self):
        """Install compact control state measured immediately before native B2."""
        shared = 0xfffffc20c0830000
        for offset, value in self.SHARED_CONTROL_NATIVE_FOURTH_WORDS:
            self._write_dva(shared + offset, struct.pack("<Q", value))
        for offset, value in self.CHANNEL_CONTROL_NATIVE_FOURTH_WORDS:
            self._write_dva(
                self.CHANNEL_CONTROL_BASE + offset, struct.pack("<Q", value))
        print(
            "  native pre-B2 shared/channel control state applied",
            flush=True,
        )

    def _patch_native_b2_primary_publication(self):
        """Install the host-owned primary scheduler state measured before B2."""
        computed = 0xfffffc20015d8000
        for offset, value, width in (
                (0x000, 0xff, 1),
                (0x008, 0xff, 1),
                (0x010, 0x0f01, 2),
                (0x018, 0x0f01, 2),
                (0x408, 2, 4),
                (0x40c, 2, 4),
                (0x604, 4, 4),
                (0x808, self.CHANNEL_CONTROL_BASE, 8),
                (0xc04, 0x1000, 4),
                (0xe00, 7, 8),
                (0xe08, 0x000000010e22618a, 8),
                (0xe20, 4, 8),
                (0xe28, 4, 8)):
            self._write_dva(
                computed + offset, int(value).to_bytes(width, "little"))

        region_1 = 0xfffffc20015e0000
        for offset, value in (
                (0x10, 0x0000008000077000),
                (0x18, 0x00000017),
                (0x1c, 0x00000017)):
            width = 8 if offset == 0x10 else 4
            self._write_dva(
                region_1 + offset, int(value).to_bytes(width, "little"))

        region_2 = 0xfffffc20015e8000
        for offset, value in (
                (0x00, 0x08000000e0000000),
                (0x08, 0x00003d4000003400),
                (0x10, 0x0000000000001d00)):
            self._write_dva(
                region_2 + offset, int(value).to_bytes(8, "little"))
        print(
            "  native pre-B2 primary scheduler-page publication applied",
            flush=True,
        )

    def _reset_muxed_channel_control(self, pair):
        """Restore the fresh per-pair control record measured before first use."""
        if pair != 1:
            raise ValueError("the fresh channel-control record is known only for pair 1")
        address = self.CHANNEL_CONTROL_BASE
        before = self._read_dva(address, self.CHANNEL_CONTROL_STRIDE)
        body = bytearray(self.CHANNEL_CONTROL_STRIDE)
        for offset, value in self.CHANNEL_CONTROL_FRESH_WORDS:
            struct.pack_into("<Q", body, offset, value)
        changed = [
            offset for offset in range(0, self.CHANNEL_CONTROL_STRIDE, 8)
            if before[offset:offset + 8] != body[offset:offset + 8]
        ]
        print(
            "  pair 1 channel control before publication differs at qwords %s" %
            (",".join("%#x" % offset for offset in changed) or "none"),
            flush=True,
        )
        self._write_dva(address, body)
        if self._read_dva(address, len(body)) != bytes(body):
            raise RuntimeError("pair 1 channel-control reset did not read back")

    def _ensure_firmware_range(self, address, size):
        """Map fresh backing for an exact firmware address when the boot lacks it."""
        from ..hw.uat import MemoryAttr
        from . import g17p_submission as submission

        page_size = submission.FIRMWARE_PAGE_SIZE
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("exact firmware mappings require an adopted upper root")
        first = address & ~(page_size - 1)
        last = (address + size + page_size - 1) & ~(page_size - 1)
        known = getattr(self, "_known_firmware_pages", set())
        self._known_firmware_pages = known
        page_keys = {
            page: (id(self.space.uat), root, page)
            for page in range(first, last, page_size)
        }
        if all(key in known for key in page_keys.values()):
            return
        # BO allocation leaves low-root page-table edits pending in this UAT
        # object. Commit them and refetch the live upper root before editing it:
        # otherwise an older cached table can be flushed wholesale while an
        # explicit-root walk is resolving a missing graph page.
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        changed = False
        for page in range(first, last, page_size):
            key = page_keys[page]
            if key in known:
                continue
            translated = self.space.uat.iotranslate_root(root, page, page_size)
            if translated and translated[0][0] is not None:
                known.add(key)
                continue
            pa = self.u.memalign(page_size, page_size)
            self.u.proxy.memset32(pa, 0, page_size)
            attr = (MemoryAttr.Normal
                    if 0xfffffc20c0000000 <= page < 0xfffffc20d0000000
                    else MemoryAttr.Shared)
            self.space.uat.iomap_at_root(
                root, page, pa, page_size, ctx=self.space.context,
                AttrIndex=attr, AP=1)
            known.add(key)
            changed = True
        if changed:
            self.space.uat.flush_dirty()
            self.space.uat.invalidate_cache()
            self.u.inst("dsb sy")
            for page in range(first, last, page_size):
                translated = self.space.uat.iotranslate_root(
                    root, page, page_size)
                if not translated or translated[0][0] is None:
                    raise RuntimeError(
                        "failed to map firmware page %#x below root %#x" %
                        (page, root))

    def map_firmware_existing_at(self, address, pa, size, attr=None):
        """Alias caller-owned physical pages into the firmware high space.

        Special objects such as timestamp buffers are ordinary caller BOs on
        the CPU side, but firmware descriptors name them through firmware-owned
        addresses.  Keep that alias operation explicit so the BO remains the
        owner of the physical storage and its firmware address can be revoked
        independently during object teardown.
        """
        from ..hw.uat import MemoryAttr
        from . import g17p_submission as submission

        page_size = submission.FIRMWARE_PAGE_SIZE
        address = int(address)
        pa = int(pa)
        size = int(size)
        if not size or (address | pa | size) & (page_size - 1):
            raise ValueError(
                "firmware aliases must be nonempty and page aligned")
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("firmware aliases require an adopted upper root")
        if attr is None:
            attr = MemoryAttr.Shared

        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        for offset in range(0, size, page_size):
            device_page = address + offset
            physical_page = pa + offset
            translated = self.space.uat.iotranslate_root(
                root, device_page, page_size)
            if translated and translated[0][0] is not None:
                if translated[0][0] != physical_page:
                    raise RuntimeError(
                        "firmware alias %#x already maps PA %#x, not %#x" %
                        (device_page, translated[0][0], physical_page))
                continue
            self.space.uat.iomap_at_root(
                root, device_page, physical_page, page_size,
                ctx=self.space.context, AttrIndex=attr,
                AP=1)

        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
        known = getattr(self, "_known_firmware_pages", set())
        self._known_firmware_pages = known
        for offset in range(0, size, page_size):
            device_page = address + offset
            physical_page = pa + offset
            translated = self.space.uat.iotranslate_root(
                root, device_page, page_size)
            if (not translated or translated[0][0] != physical_page
                    or translated[0][1] < page_size):
                raise RuntimeError(
                    "failed to create firmware alias %#x -> %#x" %
                    (device_page, physical_page))
            known.add((id(self.space.uat), root, device_page))
        return {
            "address": address,
            "pa": pa,
            "size": size,
            "root": root,
        }

    def unmap_firmware_at(self, address, size):
        """Remove a caller-owned alias from the firmware upper root."""
        from . import g17p_submission as submission

        page_size = submission.FIRMWARE_PAGE_SIZE
        address = int(address)
        size = int(size)
        if not size or (address | size) & (page_size - 1):
            raise ValueError(
                "firmware aliases must be nonempty and page aligned")
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("firmware aliases require an adopted upper root")
        unmapped = self.space.uat.iounmap_root(
            root, address, size, ctx=self.space.context)
        if unmapped != size:
            raise RuntimeError(
                "firmware alias %#x removed %#x of %#x bytes" %
                (address, unmapped, size))
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
        known = getattr(self, "_known_firmware_pages", set())
        for offset in range(0, size, page_size):
            known.discard((id(self.space.uat), root, address + offset))
        return unmapped

    def _map_descriptor_alias(self, kind, address, size):
        """Map a descriptor array page through its native low context alias."""
        from ..hw.uat import MemoryAttr
        from . import g17p_submission as submission

        high_base = self.ITEM_ARRAYS[kind][0]
        low_base = self.DESCRIPTOR_LOW_ARRAYS[kind]
        page_size = submission.FIRMWARE_PAGE_SIZE
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("descriptor aliases require an adopted upper root")
        first = address & ~(page_size - 1)
        last = (address + size + page_size - 1) & ~(page_size - 1)
        mapped = getattr(self, "_mapped_descriptor_aliases", set())
        self._mapped_descriptor_aliases = mapped
        changed = False
        for high_page in range(first, last, page_size):
            translated = self.space.uat.iotranslate_root(root, high_page, page_size)
            if not translated or translated[0][0] is None:
                raise RuntimeError("descriptor page %#x is unmapped" % high_page)
            pa = translated[0][0]
            low_page = low_base + (high_page - high_base)
            key = (id(self.space.uat), kind, high_page, low_page, pa)
            if key in mapped:
                continue
            # Descriptor self-pointers are resolved through context 0.  The
            # render context maps unrelated backing at these same VAs, so
            # publishing the alias through ``self.space.context`` corrupts that
            # context and leaves later descriptor-array pages absent from the
            # context firmware actually walks.  Native context-0 leaves are
            # Shared and executable; render-context leaves are distinct and
            # never executable.
            self.space.uat.iomap_at(
                0, low_page, pa, page_size,
                AttrIndex=MemoryAttr.Shared, AP=2, nG=1, UXN=0, OS=1)
            mapped.add(key)
            changed = True
        if not changed:
            return
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy")

    def _map_submission_primary_index_alias(self, shared_object):
        """Publish the packed shared object's low view of its primary index.

        The packed object carries the firmware-high primary-index pointer at
        ``+0x20`` and a second, full low-context pointer at ``+0x28``. Native
        topology maps both addresses to the same physical page. The low leaf is
        GPU-readable/writable Shared memory, unlike the firmware-high Normal
        leaf, so this cannot be represented by allocating only the high object.
        """
        from ..hw.uat import MemoryAttr
        from . import g17p_submission as submission

        page_size = submission.FIRMWARE_PAGE_SIZE
        body = self._read_dva(int(shared_object) + 0x20, 0x10)
        high, low = struct.unpack("<QQ", body)
        if not high or not low:
            raise RuntimeError(
                "submission shared object %#x has no primary-index aliases" %
                int(shared_object))
        if (high | low) & (page_size - 1):
            raise RuntimeError(
                "submission primary-index aliases are not page aligned: "
                "%#x/%#x" % (high, low))

        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError(
                "submission primary-index aliases require an adopted upper root")
        high_ranges = self.space.uat.iotranslate_root(
            root, high, page_size)
        high_pa = high_ranges[0][0] if high_ranges else None
        if high_pa is None:
            raise RuntimeError(
                "submission primary-index high page %#x is unmapped" % high)

        low_ranges = self.space.uat.iotranslate(
            self.space.context, low, page_size)
        low_pa = low_ranges[0][0] if low_ranges else None
        if low_pa is not None and low_pa != high_pa:
            if not self.allow_quiesced_primary_index_alias_rebind:
                raise RuntimeError(
                    "submission primary-index low alias %#x maps PA %#x, "
                    "not %#x" % (low, low_pa, high_pa))
            unmapped = self.space.uat.iounmap(
                self.space.context, low, page_size)
            if unmapped != page_size:
                raise RuntimeError(
                    "submission primary-index alias %#x removed %#x of %#x "
                    "bytes" % (low, unmapped, page_size))
            print(
                "  rebound quiesced primary-index low alias %#x from PA %#x "
                "to %#x" % (low, low_pa, high_pa),
                flush=True,
            )
            low_pa = None
        if low_pa is None:
            self.space.uat.iomap_at(
                self.space.context, low, high_pa, page_size,
                AttrIndex=MemoryAttr.Shared, AP=2, nG=1, UXN=1, OS=1)
            self.space.uat.flush_dirty()
            self.space.uat.invalidate_cache()
            self.u.inst("dsb sy")

        verified = self.space.uat.iotranslate(
            self.space.context, low, page_size)
        verified_pa = verified[0][0] if verified else None
        if verified_pa != high_pa:
            raise RuntimeError(
                "failed to create submission primary-index alias "
                "%#x/%#x -> %#x" % (high, low, high_pa))
        return {"high": high, "low": low, "pa": high_pa}

    def _map_muxed_context_aliases(self, pair):
        """Publish a created pair's low companion and firmware object."""
        from ..hw.uat import MemoryAttr
        from . import g17p_submission as submission

        pages = self.muxed_queue_context_pages.get(pair)
        if not pages:
            return
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError(
                "created queue-context aliases require an adopted upper root")
        page_size = submission.FIRMWARE_PAGE_SIZE
        key = (
            id(self.space.uat), self.space.context, pair,
            tuple(
                (kind, values["low"], values["high"],
                 tuple(values.get("low_pas", values["pas"])),
                 tuple(values["pas"]),
                 values.get("context_low_pages", 1))
                for kind, values in sorted(pages.items())
            ),
        )
        mapped = getattr(self, "_mapped_muxed_context_aliases", set())
        self._mapped_muxed_context_aliases = mapped
        if key in mapped:
            return
        for values in pages.values():
            high_pas = values["pas"]
            low_pas = values.get("low_pas", high_pas)
            context_low_pages = values.get("context_low_pages", 1)
            for index, pa in enumerate(low_pas[:context_low_pages]):
                self.space.uat.iomap_at(
                    self.space.context, values["low"] + index * page_size,
                    pa, page_size, AttrIndex=MemoryAttr.Shared, AP=1)
            for index, pa in enumerate(low_pas):
                self.space.uat.iomap_at(
                    0, values["low"] + index * page_size, pa, page_size,
                    AttrIndex=MemoryAttr.Shared, AP=2, nG=1, UXN=0, OS=1)
            for index, pa in enumerate(high_pas):
                self.space.uat.iomap_at_root(
                    root, values["high"] + index * page_size, pa, page_size,
                    ctx=self.space.context, AttrIndex=MemoryAttr.Shared, AP=1)
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy")
        for values in pages.values():
            translated = self.space.uat.iotranslate_root(
                root, values["high"], len(values["pas"]) * page_size)
            resolved = []
            for pa, size in translated:
                if pa is None:
                    resolved.extend([None] * (size // page_size))
                else:
                    resolved.extend(pa + offset for offset in range(0, size, page_size))
            if resolved != values["pas"]:
                raise RuntimeError(
                    "created queue-context object %#x mapped to %r, expected %r" %
                    (values["high"], resolved, values["pas"]))
        mapped.add(key)

    def _map_pair_status_aliases(self, pair):
        """Make a created pair's render and firmware status pointers coherent."""
        map_aliases = (
            os.getenv("G17P_NATIVE_ITEM_FIELDS") == "1"
            or os.getenv("G17P_NATIVE_STATUS_ALIASES") == "1")
        if not map_aliases:
            return
        from ..hw.uat import MemoryAttr
        from .g17p_backend import G17PWorkBuilder
        from . import g17p_submission as submission

        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("pair status aliases require an adopted upper root")
        page_size = submission.FIRMWARE_PAGE_SIZE
        initialized = getattr(self, "initialized_pair_status_aliases", set())
        self.initialized_pair_status_aliases = initialized
        mapped = getattr(self, "_mapped_pair_status_aliases", set())
        self._mapped_pair_status_aliases = mapped
        changed = False
        for kind in ("tiling", "fragment"):
            high = G17PWorkBuilder.PAIR_STATUS_BASES[kind][pair]
            self._ensure_firmware_range(high, page_size)
            translated = self.space.uat.iotranslate_root(root, high, page_size)
            if not translated or translated[0][0] is None:
                raise RuntimeError(
                    "%s pair-%d status page %#x is unmapped" %
                    (kind, pair, high))
            pa = translated[0][0] & ~(page_size - 1)
            low = self.PAIR_RENDER_STATUS_BASES[kind][pair]
            key = (pair, kind)
            if key not in initialized:
                self.u.proxy.memset32(pa, 0, page_size)
                self.u.proxy.dc_civac(pa, page_size)
                initialized.add(key)
            map_key = (id(self.space.uat), self.space.context, pair, kind, low, pa)
            if map_key in mapped:
                continue
            self.space.uat.iomap_at(
                self.space.context, low, pa, page_size,
                AttrIndex=MemoryAttr.Normal, AP=2, nG=1, UXN=1, OS=1)
            obj = self.render_objects.get(
                "ta_status" if kind == "tiling" else "fragment_status")
            if obj is not None and obj._addr == low:
                obj._pa = pa
            mapped.add(map_key)
            changed = True
        if not changed:
            return
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy")

    def create_queue_pair(self, pair, optional_pointers, job_list_addr=None,
                          uuid=0xa6):
        """Build the queue records a channel pair needs, in firmware's own space.

        A pair whose ring slot names no queue has nothing to publish onto. Building one is what a
        driver does when it opens a second context, and it needs a pointer block, an item ring
        and a record for each of the two channels. The record's context object is the same object
        the pair's optional items name as their channel control.
        """
        from . import g17p

        built = {}
        # One job list for the pair, not one per channel. Both of the boot's queues name the same
        # head, and a pair given two heads completes its first group and then fetches without
        # completing, which is what a separate head per channel produced here.
        if job_list_addr is None:
            job_list_addr = self._alloc_graph(g17p.JOB_LIST_SIZE, "pair%d_job_list" % pair)
            self._write_dva(job_list_addr, g17p.build_job_list(job_list_addr))

        for kind, name in (("tiling", "TA_%d" % pair), ("fragment", "3D_%d" % pair)):
            entry = self.channels.by_name(name)
            if entry is None:
                raise RuntimeError("channel %s is absent from the table" % name)
            existing = struct.unpack("<Q", self._read_dva(entry["ring_addr"] + 8, 8))[0]
            if existing:
                built[name] = {"queue": existing, "reused": True}
                continue
            pointers = self._alloc_graph(max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80),
                                         "%s_pointers" % name)
            self._write_dva(pointers, bytes(max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80)))
            self._write_dva(pointers, g17p.build_queue_pointers())
            # Two words a host initialises in the pointer block besides the indices. A freshly
            # zeroed block has neither, and the init pair only ever appeared to work without them
            # because its block comes seeded.
            for offset, value in self.QUEUE_POINTER_FIELDS:
                self._write_dva(pointers + offset, struct.pack("<I", value))
            item_ring = self._alloc_graph(0x4000, "%s_item_ring" % name)
            self._write_dva(item_ring, bytes(0x4000))
            head = job_list_addr
            queue_addr = self._alloc_graph(g17p.QUEUE_RECORD_STRIDE, "%s_queue" % name)
            self._write_dva(queue_addr, g17p.build_queue_record(
                pointers_addr=pointers, ring_addr=item_ring,
                job_list_addr=head,
                context_addr=optional_pointers[kind]["channel_control"],
                uuid=uuid))
            # The record's fixed furniture, identical in both queues of a working host's created
            # pair and of its init pair, so not per-queue.
            for offset, value in self.QUEUE_RECORD_FIELDS:
                self._write_dva(queue_addr + offset, struct.pack("<Q", value))
            self._write_dva(entry["ring_addr"] + g17p.RING_SLOT_QUEUE_PTR,
                            struct.pack("<Q", queue_addr))
            built[name] = {"queue": queue_addr, "pointers": pointers,
                           "item_ring": item_ring, "job_list": head, "reused": False}
        return built

    NATIVE_PARTIAL_OPENING_JOB_LIST = 0xfffffc2000000000
    NATIVE_PARTIAL_OPENING_SHARED_CONTROL = 0xfffffc20c0828000
    NATIVE_PARTIAL_OPENING_UUID = 0xac

    def _apply_native_partial_opening_queue(self, queues):
        """Rebind the cold-boot grid-0/1 pair to partial's opening owner.

        Native's synchronized forced-partial trace uses the already allocated
        grid-0/1 queue records, but they are not the init-pair ownership
        records present in the generic cold-boot seed.  Before their first
        producer becomes visible, both queues instead name scheduler head 0,
        channel-control record 0, and queue identity 0xac.  The following
        grid-2/3 incarnation takes head/record 1, so swapping these roles after
        work starts is too late: class 2 observes the wrong firmware-produced
        history and faults.
        """
        from . import g17p

        if self.native_partial_opening_queue_applied:
            return
        job_list = self.NATIVE_PARTIAL_OPENING_JOB_LIST
        channel_control = self.CHANNEL_CONTROL_BASE
        self._write_dva(job_list, g17p.build_job_list(job_list))
        for kind in ("tiling", "fragment"):
            _entry, queue = queues[kind]
            for offset, value, width in (
                    (g17p.QUEUE_JOB_LIST_ADDR, job_list, 8),
                    (g17p.QUEUE_UUID, self.NATIVE_PARTIAL_OPENING_UUID, 4),
                    (g17p.QUEUE_CONTEXT_ADDR, channel_control, 8)):
                self._write_dva(
                    queue.address + offset,
                    int(value).to_bytes(width, "little"))
            queue.job_list_addr = job_list
            queue.record["job_list_addr"] = job_list
            queue.record["uuid"] = self.NATIVE_PARTIAL_OPENING_UUID
            queue.record["context_addr"] = channel_control
            self._clean_dva_range(queue.address, g17p.QUEUE_RECORD_STRIDE)
        self._clean_dva_range(job_list, g17p.JOB_LIST_SIZE)
        self.u.inst("dsb sy")
        self.native_partial_opening_queue_applied = True
        print(
            "  native partial opening queues bind job list %#x, channel "
            "control %#x, UUID %#x" % (
                job_list, channel_control,
                self.NATIVE_PARTIAL_OPENING_UUID),
            flush=True,
        )

    def create_muxed_queue_pair(self, pair, optional_pointers, job_list_addr=None,
                                uuid=0xa6, channel_pair=0, recreate=False,
                                reserve_graph=True):
        """Create queue pair ``pair`` on an existing work-channel pair.

        Queue grids and work channels are separate dimensions. A native stream uses
        queue grids 0/1 and 2/3 on the TA_0/3D_0 channel rings; selecting TA_1/3D_1
        for the second queue pair instead puts work on different channels and is not
        the observed context-switching mechanism.
        """
        from . import g17p
        from . import g17p_submission as submission
        from .g17p_backend import G17PQueue

        if pair in self.muxed_queue_pairs:
            return self.muxed_queue_pairs[pair]
        if pair < 0:
            raise ValueError("queue pair must be non-negative")
        if pair in self.destroyed_muxed_queue_pairs and not recreate:
            raise G17PUnsupported(
                "muxed queue pair %d was destroyed and must be explicitly recreated" % pair)

        partial_pre_class2_pair1 = bool(
            pair == 1 and channel_pair == 2
            and getattr(self, "partial_pre_class2_pair1_profile", False))
        native_context2 = pair in (2, 3) and (
            channel_pair == 2 or self.native_context2_primary_channel)
        native_pair2 = pair == 2 and native_context2
        native_pair3 = pair == 3 and native_context2
        native_context4 = pair == 4 and channel_pair == 2
        partial_pair2 = bool(
            native_pair2 and getattr(self, "partial_render_pair2_profile", False))
        pair_uuid = (self.PARTIAL_PRE_CLASS2_PAIR1_UUID
                     if partial_pre_class2_pair1 else
                     self.PARTIAL_PAIR2_UUID if partial_pair2 else
                     self.NATIVE_PAIR2_UUID if native_pair2 else
                     self.NATIVE_PAIR3_UUID if native_pair3 else
                     self.NATIVE_PAIR4_UUID if native_context4 else uuid)
        fresh_queue_context = None
        if partial_pair2 and self.partial_fresh_transport_topology:
            if not self.partial_fresh_queue_generation:
                raise G17PUnsupported(
                    "fresh partial transport topology requires a fresh queue generation")
            fresh_queue_context = self._alloc_graph(
                g17p.QUEUE_CONTEXT_STRIDE,
                "mux_pair%d_queue_context" % pair)
            self._write_dva(
                fresh_queue_context,
                self._read_dva(
                    self.PARTIAL_PAIR2_CHANNEL_CONTROL,
                    g17p.QUEUE_CONTEXT_STRIDE))
        if job_list_addr is None:
            # The initial pair uses the second head and the host-created pair the
            # first. Both live in the same low page and are initialized circular
            # lists before the pair is published.
            job_list_addr = (self._alloc_graph(
                                 g17p.JOB_LIST_SIZE,
                                 "mux_pair%d_fresh_job_list" % pair)
                             if fresh_queue_context is not None else
                             self.PARTIAL_PRE_CLASS2_PAIR1_JOB_LIST
                             if partial_pre_class2_pair1 else
                             0xfffffc2000000000 if pair == 1 else
                             self.PARTIAL_PAIR2_JOB_LIST if partial_pair2 else
                             self.NATIVE_PAIR4_JOB_LIST if native_context4 else
                             self.NATIVE_CONTEXT2_JOB_LIST if native_context2 else
                             self._alloc_graph(
                                 g17p.JOB_LIST_SIZE,
                                 "mux_pair%d_job_list" % pair))
        self._write_dva(job_list_addr, g17p.build_job_list(job_list_addr))

        pair_pointers = {kind: dict(values)
                         for kind, values in optional_pointers.items()}
        if native_context2:
            for values in pair_pointers.values():
                values["channel_control"] = (
                    self.PARTIAL_PAIR2_CHANNEL_CONTROL if partial_pair2
                    else self.NATIVE_CONTEXT2_CHANNEL_CONTROL)
                values["shared_control"] = (
                    self.PARTIAL_PAIR2_SHARED_CONTROL if partial_pair2
                    else self.NATIVE_PAIR2_SHARED_CONTROL if native_pair2
                    else self.NATIVE_PAIR3_SHARED_CONTROL)
                # The partial optional record carries identity 3 at +0x32,
                # descriptor context 2 at +0x56, and scheduler class 2.  The
                # fields are independent even though earlier records happened
                # to give them equal values.
                values["context_id"] = 3 if partial_pair2 else 2
                values["uuid"] = pair_uuid
                if partial_pair2:
                    values["scheduler_class"] = 2
                    values["submission_ordinal_base"] = (
                        self.PARTIAL_PAIR2_OPTIONAL_ORDINAL)
                    values["queue_context_index_base"] = 0
                    values["queue_context_phase_base"] = 0
                    values.pop("queue_context_phase", None)
                    # First-record flags follow the logical item.  Item zero
                    # retains them; the replay-shaped item one clears them.
                    values["first_record"] = None
                    values["u16_overrides"] = {0x46: 1, 0x56: 2}
            exact_queues = ({} if (
                partial_pair2 and self.partial_fresh_queue_generation) else
                self.PARTIAL_PAIR2_QUEUES if partial_pair2 else
                            self.NATIVE_PAIR2_QUEUES if native_pair2
                            else self.NATIVE_PAIR3_QUEUES)
            for spec in exact_queues.values():
                self._ensure_firmware_range(
                    spec["pointers"], max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
                self._ensure_firmware_range(
                    spec["item_ring"], self.NATIVE_CONTEXT2_ITEM_RING_SIZE)
                self._ensure_firmware_range(
                    spec["queue"], g17p.QUEUE_RECORD_STRIDE)
        elif native_context4:
            for kind, values in pair_pointers.items():
                values["channel_control"] = self.NATIVE_PAIR4_CHANNEL_CONTROL
                values["shared_control"] = self.NATIVE_PAIR4_SHARED_CONTROL
                values["context_id"] = 4
                values["uuid"] = pair_uuid
                values["scheduler_class"] = 2
                values["submission_ordinal_base"] = (
                    self.NATIVE_PAIR4_SUBMISSION_ORDINAL)
                values["lifecycle_ordinal"] = (
                    self.NATIVE_PAIR4_LIFECYCLE_ORDINAL)
                # Context 4's measured TA queue-context carries two preceding
                # selector-3 records; fragment starts at its first slot.
                values["queue_context_index_base"] = (
                    2 if kind == "tiling" else 0)
                values["queue_context_phase"] = 0
                values["first_record"] = True
                values["queue_namespace"] = 4
            for spec in self.NATIVE_PAIR4_QUEUES.values():
                self._ensure_firmware_range(
                    spec["pointers"], max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
                self._ensure_firmware_range(spec["item_ring"], 0x4000)
                self._ensure_firmware_range(
                    spec["queue"], g17p.QUEUE_RECORD_STRIDE)
        context_aliases = self.MUX_PAIR_CONTEXTS.get(pair)
        if context_aliases is not None:
            context_pages = {}
            for kind, aliases in context_aliases.items():
                high_pas = [
                    self.u.memalign(submission.FIRMWARE_PAGE_SIZE,
                                    submission.FIRMWARE_PAGE_SIZE)
                    for _ in range(self.MUX_PAIR1_CONTEXT_PAGES)
                ]
                low_pas = ([
                    self.u.memalign(submission.FIRMWARE_PAGE_SIZE,
                                    submission.FIRMWARE_PAGE_SIZE)
                    for _ in range(self.MUX_PAIR1_CONTEXT_PAGES)
                ] if native_context4 else high_pas)
                initial = (submission.build_queue_context(kind, pair=pair)
                           if pair == 1 else bytes(submission.FIRMWARE_PAGE_SIZE))
                self.u.iface.writemem(high_pas[0], initial)
                self.u.proxy.dc_civac(
                    high_pas[0], submission.FIRMWARE_PAGE_SIZE)
                for pa in high_pas[1:]:
                    self.u.proxy.memset32(pa, 0, submission.FIRMWARE_PAGE_SIZE)
                    self.u.proxy.dc_civac(pa, submission.FIRMWARE_PAGE_SIZE)
                if native_context4:
                    for pa in low_pas:
                        self.u.proxy.memset32(
                            pa, 0, submission.FIRMWARE_PAGE_SIZE)
                        self.u.proxy.dc_civac(
                            pa, submission.FIRMWARE_PAGE_SIZE)
                context_pages[kind] = dict(
                    aliases, pa=high_pas[0], pas=high_pas,
                    low_pas=low_pas,
                    context_low_pages=(len(low_pas) if native_context4 else 1))
                pair_pointers[kind]["context_scratch"] = aliases["low"]
                pair_pointers[kind]["firmware_scratch"] = aliases["high"]
                if pair == 1:
                    pair_pointers[kind]["channel_control"] = (
                        self.PARTIAL_PRE_CLASS2_PAIR1_CHANNEL_CONTROL
                        if partial_pre_class2_pair1 else
                        self.CHANNEL_CONTROL_BASE)
            self.muxed_queue_context_pages[pair] = context_pages
            self._map_muxed_context_aliases(pair)

        if pair == 1:
            pair1_queues = (self.PARTIAL_PRE_CLASS2_PAIR1_QUEUES
                            if partial_pre_class2_pair1 else
                            self.MUX_PAIR1_QUEUES)
            for spec in pair1_queues.values():
                self._ensure_firmware_range(
                    spec["pointers"], max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
                self._ensure_firmware_range(spec["item_ring"], 0x4000)
                self._ensure_firmware_range(spec["queue"], g17p.QUEUE_RECORD_STRIDE)
            if reserve_graph:
                for _name, address, size in self.MUX_PAIR1_GRAPH:
                    self._ensure_firmware_range(address, size)
        elif native_pair2:
            graph = (self.PARTIAL_PAIR2_GRAPH if partial_pair2
                     else self.MUX_PAIR2_GRAPH)
            for _name, address, size in graph:
                self._ensure_firmware_range(address, size)
        elif native_pair3 or native_context4:
            for _name, address, size in self.MUX_PAIR3_GRAPH:
                self._ensure_firmware_range(address, size)

        if partial_pair2:
            # Partial's optional items and descriptor tails bind a control
            # object which is deliberately distinct from this graph's
            # secondary-index page.  Direct-compute happened to map both this
            # page and its low child before pair creation; the ordinary render
            # lifetime does not.  A created pair must own the complete pointer
            # closure instead of depending on whichever bootstrap preceded it.
            from . import g17p_compute

            control = self.PARTIAL_PAIR2_SHARED_CONTROL
            inner = self.PARTIAL_PAIR2_SHARED_CONTROL_INNER
            self._ensure_firmware_range(
                control, submission.FIRMWARE_PAGE_SIZE)
            self._ensure_firmware_range(
                inner, submission.FIRMWARE_PAGE_SIZE)
            control_body = g17p_compute.build_compute_shared_support(
                self.PARTIAL_PAIR2_CONTROL_OPERAND,
                inner,
                word_08=1,
                word_10=2,
                header=3,
                resource_class=0x19,
                cursor=0xE0,
                field_54=2,
                field_5c=0,
                final_kind=3,
            )
            self._write_dva(control, control_body)
            self._write_dva(inner, struct.pack("<Q", 4))
            self._clean_dva_range(control, len(control_body))
            self._clean_dva_range(inner, 8)
            self.u.inst("dsb sy")
            print(
                "  pair 2 built shared-control closure %#x -> %#x" % (
                    control, inner),
                flush=True,
            )

        self.muxed_queue_pointer_sets[pair] = pair_pointers

        queues = {}
        built = {}
        for kind, prefix, kind_index in (
                ("tiling", "TA", 0), ("fragment", "3D", 1)):
            channel_name = "%s_%d" % (prefix, channel_pair)
            entry = self.channels.by_name(channel_name)
            fallback_grid_index = pair * 2 + kind_index
            exact = ((self.PARTIAL_PRE_CLASS2_PAIR1_QUEUES
                      if partial_pre_class2_pair1 else
                      self.MUX_PAIR1_QUEUES).get(kind) if pair == 1 else
                     None if (partial_pair2
                              and self.partial_fresh_queue_generation) else
                     self.PARTIAL_PAIR2_QUEUES.get(kind)
                     if partial_pair2 else
                     self.NATIVE_PAIR2_QUEUES.get(kind) if native_pair2 else
                     self.NATIVE_PAIR3_QUEUES.get(kind) if native_pair3 else
                     self.NATIVE_PAIR4_QUEUES.get(kind)
                     if native_context4 else None)
            pointers = (exact["pointers"] if exact is not None else
                        self._alloc_graph(
                            max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80),
                            "mux_pair%d_%s_pointers" % (pair, kind)))
            self._write_dva(
                pointers, bytes(max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80)))
            self._write_dva(pointers, g17p.build_queue_pointers())
            for offset, value in self.QUEUE_POINTER_FIELDS:
                self._write_dva(pointers + offset, struct.pack("<I", value))
            item_ring = (exact["item_ring"] if exact is not None else
                         self._alloc_graph(
                             0x4000, "mux_pair%d_%s_item_ring" % (pair, kind)))
            item_ring_size = (self.NATIVE_CONTEXT2_ITEM_RING_SIZE
                              if native_context2 else 0x4000)
            self._write_dva(item_ring, bytes(item_ring_size))
            queue_addr = (exact["queue"] if exact is not None else
                          self._alloc_graph(
                              g17p.QUEUE_RECORD_STRIDE,
                              "mux_pair%d_%s_queue" % (pair, kind)))
            grid_index = grid_index_from_queue_address(
                queue_addr, fallback_grid_index)
            scheduled_queue = bool(
                native_context2 or native_context4
                or partial_pre_class2_pair1)
            self._write_dva(queue_addr, g17p.build_queue_record(
                pointers_addr=pointers,
                ring_addr=item_ring,
                job_list_addr=job_list_addr,
                context_addr=(fresh_queue_context
                              if fresh_queue_context is not None else
                              pair_pointers[kind]["channel_control"]),
                uuid=pair_uuid,
                priority=2 if scheduled_queue else 0,
                prio5=2 if scheduled_queue else 1,
                unk_2c=2 if scheduled_queue else 0,
                unk_38=0 if scheduled_queue else 1,
                sentinel_size=2 if scheduled_queue else
                g17p.QUEUE_SENTINEL_SIZE))
            if partial_pair2 and self.partial_replay_queue_live_fields:
                self._write_dva(
                    queue_addr + g17p.QUEUE_GPU_RPTR2,
                    struct.pack("<I", 3))
                self._write_dva(
                    queue_addr + g17p.QUEUE_UNK_94,
                    struct.pack(
                        "<I", 0x136904 if kind == "tiling" else 0x1381c6))
            if not scheduled_queue:
                for offset, value in self.QUEUE_RECORD_FIELDS:
                    self._write_dva(
                        queue_addr + offset, struct.pack("<Q", value))
            queue = G17PQueue(self._read_dva, queue_addr, grid_index)
            queues[kind] = (entry, queue)
            built[channel_name] = {
                "queue": queue_addr,
                "pointers": pointers,
                "item_ring": item_ring,
                "job_list": job_list_addr,
                "grid_index": grid_index,
                "reused": False,
            }

        if fresh_queue_context is not None:
            print(
                "  pair %d fresh transport context %#x copied from %#x; "
                "shared job list %#x" % (
                    pair, fresh_queue_context,
                    self.PARTIAL_PAIR2_CHANNEL_CONTROL, job_list_addr),
                flush=True,
            )

        if recreate:
            for details in built.values():
                self._clean_dva_range(
                    details["queue"], g17p.QUEUE_RECORD_STRIDE)
                self._clean_dva_range(
                    details["pointers"],
                    max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
                self._clean_dva_range(details["item_ring"], 0x4000)
            self._clean_dva_range(job_list_addr, g17p.JOB_LIST_SIZE)
            self.u.inst("dsb sy")
        self.muxed_queue_pairs[pair] = queues
        self.muxed_queue_pair_generations.setdefault(pair, 0)
        self.destroyed_muxed_queue_pairs.discard(pair)
        return built

    def _clean_dva_range(self, address, size):
        """Publish CPU writes to one firmware- or render-address range."""
        if self.firmware_root == "high" and address >= 0xffff000000000000:
            root = getattr(self, "firmware_high_root", None) or self.space.uat.ttbr1_base
            ranges = self.space.uat.iotranslate_root(root, address, size)
        else:
            ranges = self.space.uat.iotranslate(self.space.context, address, size)
        remaining = size
        for pa, span in ranges:
            if pa is None:
                raise RuntimeError("cannot clean unmapped DVA %#x" % address)
            length = min(span, remaining)
            self.u.proxy.dc_civac(pa, length)
            remaining -= length
            if not remaining:
                return
        raise RuntimeError(
            "translation for %#x covered %#x of %#x bytes" % (
                address, size - remaining, size))

    def acknowledge_report_channels(self):
        """Return firmware-owned report credits to both firmware instances.

        Report-channel state pointers zero and two each name a split counter
        object. The pointer names the host-owned acknowledgement and `+0x20`
        names firmware's peer. A stale host half eventually exhausts the shared
        256-credit admission lifecycle and prevents outer work-ring reuse.
        """
        from . import g17p

        if not self.ack_report_channels:
            return []

        tables = [("primary", self.channels)]
        if self.secondary_channels is not None:
            tables.append(("secondary", self.secondary_channels))
        changed = []
        for instance, channels in tables:
            for channel_index in g17p.REPORT_CHANNEL_INDICES:
                entry = channels.entries[channel_index]
                for state_index in g17p.REPORT_STATE_INDICES:
                    host = entry["state_addrs"][state_index]
                    if not host:
                        continue
                    peer = host + g17p.REPORT_PEER_OFFSET
                    self._clean_dva_range(
                        host, g17p.REPORT_PEER_OFFSET + 4)
                    host_value = struct.unpack(
                        "<I", self._read_dva(host, 4))[0]
                    peer_value = struct.unpack(
                        "<I", self._read_dva(peer, 4))[0]
                    if host_value == peer_value:
                        continue
                    self._write_dva(host, struct.pack("<I", peer_value))
                    self._clean_dva_range(host, 4)
                    changed.append({
                        "instance": instance,
                        "channel": channel_index,
                        "state": state_index,
                        "before": host_value,
                        "after": peer_value,
                    })
        if changed:
            self.u.inst("dsb sy")
        return changed

    def snapshot_report_channel_states(self):
        """Read the mapped host/firmware state words for report channels.

        These addresses are ordinary firmware-shared memory from the channel
        table.  They are safe diagnostics on T8140, unlike guessed SGX MMIO
        offsets.  State pointers zero and two are split credit counters; state
        pointer one is recorded without interpreting it as an acknowledgement.
        """
        from . import g17p

        tables = [("primary", self.channels)]
        if self.secondary_channels is not None:
            tables.append(("secondary", self.secondary_channels))
        snapshot = []
        for instance, channels in tables:
            for channel_index in g17p.REPORT_CHANNEL_INDICES:
                entry = channels.entries[channel_index]
                states = []
                for state_index, address in enumerate(entry["state_addrs"]):
                    if not address:
                        states.append(None)
                        continue
                    value = struct.unpack(
                        "<I", self._read_dva(address, 4))[0]
                    state = {"address": address, "value": value}
                    if state_index in g17p.REPORT_STATE_INDICES:
                        state["peer"] = struct.unpack(
                            "<I", self._read_dva(
                                address + g17p.REPORT_PEER_OFFSET, 4))[0]
                    states.append(state)
                snapshot.append({
                    "instance": instance,
                    "channel": channel_index,
                    "ring": entry["ring_addr"],
                    "states": states,
                })
        return snapshot

    def destroy_muxed_queue_pair(self, pair, channel_pair=0):
        """Retire and remove one completed host-created TA/3D queue pair.

        Queue completion is a precondition, not inferred here as rendering:
        callers must separately prove semantic completion from the target BO.
        Once both work channels are idle, their consumed slots are no longer
        firmware-owned and may be cleared along with the queue records.  Pair
        zero is firmware's bootstrap pair and is intentionally excluded until
        its independent lifetime is established.
        """
        from . import g17p
        from . import g17p_submission as submission

        pair = int(pair)
        if pair <= 0:
            raise G17PUnsupported(
                "only host-created muxed queue pairs can currently be destroyed")
        if pair in self.destroyed_muxed_queue_pairs:
            return self.muxed_queue_pair_tombstones[pair]
        queues = self.muxed_queue_pairs.get(pair)
        if queues is None:
            raise KeyError("muxed queue pair %d has not been created" % pair)

        pending_fences = self.fence_tracker.outstanding(queue_pair=pair)
        if pending_fences:
            raise RuntimeError(
                "muxed queue pair %d still owns %d pending submission fence(s)" %
                (pair, len(pending_fences)))

        queue_addresses = set()
        queue_ids = set()
        entries = {}
        for kind, prefix in (("tiling", "TA"), ("fragment", "3D")):
            entry, queue = queues[kind]
            indices = queue.indices()
            if not (indices["done"] == indices["read"] == indices["write"]):
                raise RuntimeError(
                    "%s queue %#x is not idle: %r" % (
                        kind, queue.address, indices))
            counters = self.channels.counters(entry)
            if not (counters[0] == counters[1] == counters[2]):
                raise RuntimeError(
                    "%s work channel is not idle: %r" % (kind, counters))
            queue_addresses.add(queue.address)
            queue_ids.add(queue.record["uuid"])
            entries[kind] = entry
        if len(queue_ids) != 1:
            raise RuntimeError(
                "queue-pair identifiers disagree: %r" % sorted(queue_ids))

        job_lists = {queue.job_list_addr for _entry, queue in queues.values()}
        for address in job_lists:
            self._write_dva(address, g17p.build_job_list(address))
            self._clean_dva_range(address, g17p.JOB_LIST_SIZE)
            parsed = g17p.parse_job_list(
                self._read_dva(address, g17p.JOB_LIST_SIZE),
                own_address=address)
            if not parsed.get("empty"):
                raise RuntimeError("job list %#x did not reset to empty" % address)

        cleared_slots = {}
        for kind, entry in entries.items():
            ring_size = g17p.RING_SLOT_COUNT * g17p.RING_SLOT_SIZE
            body = self._read_dva(entry["ring_addr"], ring_size)
            matches = []
            for index in range(g17p.RING_SLOT_COUNT):
                offset = index * g17p.RING_SLOT_SIZE
                queue_address = struct.unpack_from(
                    "<Q", body, offset + g17p.RING_SLOT_QUEUE_PTR)[0]
                if queue_address not in queue_addresses:
                    continue
                self._write_dva(
                    entry["ring_addr"] + offset, bytes(g17p.RING_SLOT_SIZE))
                self._clean_dva_range(
                    entry["ring_addr"] + offset, g17p.RING_SLOT_SIZE)
                matches.append(index)
            cleared_slots[kind] = matches

        current_job_base = 0xfffffc20c07d0000
        cleared_current_jobs = []
        for offset in (0, 0x40):
            record = self._read_dva(current_job_base + offset, 0x40)
            queue_address = struct.unpack_from("<Q", record, 0x38)[0]
            if queue_address not in queue_addresses:
                continue
            self._write_dva(current_job_base + offset, bytes(0x40))
            self._clean_dva_range(current_job_base + offset, 0x40)
            cleared_current_jobs.append(offset)

        specs = {}
        for kind, (_entry, queue) in queues.items():
            specs[kind] = {
                "queue": queue.address,
                "pointers": queue.pointers_addr,
                "item_ring": queue.item_ring,
                "job_list": queue.job_list_addr,
            }
            self._write_dva(queue.address, bytes(g17p.QUEUE_RECORD_STRIDE))
            self._write_dva(
                queue.pointers_addr,
                bytes(max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80)))
            self._write_dva(queue.item_ring, bytes(0x4000))
            self._clean_dva_range(queue.address, g17p.QUEUE_RECORD_STRIDE)
            self._clean_dva_range(
                queue.pointers_addr, max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
            self._clean_dva_range(queue.item_ring, 0x4000)

        context_pages = self.muxed_queue_context_pages[pair]
        root = getattr(self, "firmware_high_root", None)
        if root is None:
            raise RuntimeError("queue-context removal requires an adopted upper root")
        page_size = submission.FIRMWARE_PAGE_SIZE
        old_context_pas = {}
        for kind, values in context_pages.items():
            low_pas = values.get("low_pas", values["pas"])
            old_context_pas[kind] = tuple(low_pas) + tuple(values["pas"])
            self.space.uat.iounmap(
                self.space.context, values["low"],
                values.get("context_low_pages", 1) * page_size)
            self.space.uat.iounmap(
                0, values["low"], len(low_pas) * page_size)
            self.space.uat.iounmap_root(
                root, values["high"], len(values["pas"]) * page_size,
                ctx=self.space.context)
        self.space.uat.flush_dirty()
        self.space.uat.invalidate_cache()
        self.u.inst("dsb sy")

        for values in context_pages.values():
            checks = (
                self.space.uat.iotranslate(
                    self.space.context, values["low"],
                    values.get("context_low_pages", 1) * page_size),
                self.space.uat.iotranslate(
                    0, values["low"], len(low_pas) * page_size),
                self.space.uat.iotranslate_root(
                    root, values["high"], len(values["pas"]) * page_size),
            )
            if any(any(pa is not None for pa, _span in result)
                   for result in checks):
                raise RuntimeError(
                    "destroyed queue-context aliases still translate: %r" %
                    (checks,))

        tombstone = {
            "pair": pair,
            "channel_pair": channel_pair,
            "optional_pointers": {
                kind: dict(values) for kind, values in
                self.muxed_queue_pointer_sets[pair].items()
            },
            "job_list": next(iter(job_lists)),
            "queues": specs,
            "old_context_pas": old_context_pas,
            "uuid": next(iter(queue_ids)),
            "generation": self.muxed_queue_pair_generations.get(pair, 0),
            "submission_count": self.queue_pair_submissions.get(pair, 0),
            "cleared_slots": cleared_slots,
            "cleared_current_jobs": cleared_current_jobs,
            "scheduler_graph_will_rebuild": pair in self.paired_builders,
        }
        self.muxed_queue_pair_tombstones[pair] = tombstone
        del self.muxed_queue_pairs[pair]
        del self.muxed_queue_pointer_sets[pair]
        del self.muxed_queue_context_pages[pair]
        self.queue_pair_submissions.pop(pair, None)
        self.reusable_queue_items.pop((channel_pair, pair), None)
        removed_builder = self.paired_builders.pop(pair, None)
        if self.paired_builder is removed_builder:
            self.paired_builder = None
        self.destroyed_muxed_queue_pairs.add(pair)
        return tombstone

    def recreate_muxed_queue_pair(self, pair):
        """Explicitly recreate a destroyed pair at its firmware-visible slots."""
        pair = int(pair)
        tombstone = self.muxed_queue_pair_tombstones.get(pair)
        if tombstone is None or pair not in self.destroyed_muxed_queue_pairs:
            raise G17PUnsupported(
                "muxed queue pair %d has no destroyed generation to recreate" % pair)
        generation = tombstone["generation"] + 1
        uuid = tombstone["uuid"]
        built = self.create_muxed_queue_pair(
            pair,
            tombstone["optional_pointers"],
            job_list_addr=tombstone["job_list"],
            uuid=uuid,
            channel_pair=tombstone["channel_pair"],
            recreate=True)
        self.muxed_queue_pair_generations[pair] = generation
        self.queue_pair_submissions[pair] = tombstone["submission_count"]
        new_pas = {
            kind: (tuple(values.get("low_pas", values["pas"]))
                   + tuple(values["pas"]))
            for kind, values in self.muxed_queue_context_pages[pair].items()
        }
        if any(new_pas[kind] == tombstone["old_context_pas"][kind]
               for kind in new_pas):
            raise RuntimeError("recreated queue pair reused old context backing")
        return {"built": built, "context_pas": new_pas,
                "uuid": uuid, "generation": generation,
                "tombstone": tombstone}

    def muxed_queue_pair(self, pair, channel_pair=0):
        """Return a queue pair multiplexed on ``channel_pair``.

        Pair zero is firmware's initial pair and is discovered from slot zero.
        Later pairs must have been created with :meth:`create_muxed_queue_pair`.
        """
        if pair in self.muxed_queue_pairs:
            return self.muxed_queue_pairs[pair]
        if pair in self.destroyed_muxed_queue_pairs:
            raise G17PUnsupported(
                "muxed queue pair %d has been destroyed" % pair)
        if pair != 0:
            raise KeyError("muxed queue pair %d has not been created" % pair)
        queues = {
            "tiling": self.queue_for("TA_%d" % channel_pair),
            "fragment": self.queue_for("3D_%d" % channel_pair),
        }
        self.muxed_queue_pairs[pair] = queues
        return queues

    def set_muxed_queue_priority(self, pair, priority, channel_pair=0):
        """Apply one coherent firmware priority profile to an idle pair.

        Logical DRM queues are serialized over the native queue-pair cadence.
        Priority is therefore selected immediately before publication, after
        the preceding synchronous submission has retired.  Only the
        host-owned priority family at +0x28..+0x44 is changed; queue pointers,
        identifiers, and firmware-owned completion state remain intact.
        """
        from . import g17p

        priority = int(priority)
        profile = g17p.queue_priority_profile(priority)
        queues = self.muxed_queue_pair(int(pair), channel_pair=channel_pair)
        for kind, (_entry, queue) in queues.items():
            indices = queue.indices()
            idle = indices["done"] == indices["read"] == indices["write"]
            unpublished_opening = (
                self.group_number == 0
                and getattr(self, "last_submission", None) is None
                and indices["done"] == indices["read"] == 0
                and indices["write"] > 0
                and indices["write"] % 3 == 0)
            if not (idle or unpublished_opening):
                raise RuntimeError(
                    "cannot change %s queue priority while indices are live: %r"
                    % (kind, indices))
            record = bytearray(self._read_dva(
                queue.address, g17p.QUEUE_DESCRIPTOR_SIZE))
            struct.pack_into(
                "<I", record, g17p.QUEUE_PRIORITY, profile["priority"])
            struct.pack_into(
                "<I", record, g17p.QUEUE_UNK_2C, profile["unk_2c"])
            struct.pack_into(
                "<Q", record, g17p.QUEUE_UNK_30, profile["unk_30"])
            struct.pack_into(
                "<I", record, g17p.QUEUE_UNK_38, profile["unk_38"])
            struct.pack_into("<I", record, g17p.QUEUE_UNK_3C, 0)
            struct.pack_into(
                "<I", record, g17p.QUEUE_PRIO5, profile["prio5"])
            struct.pack_into("<i", record, g17p.QUEUE_UNK_44, -1)
            start = g17p.QUEUE_PRIORITY
            end = g17p.QUEUE_UUID
            self._write_dva(queue.address + start, record[start:end])
            queue.record = g17p.parse_queue_record(bytes(record))
            self._clean_dva_range(queue.address + start, end - start)
        self.u.inst("dsb sy")
        self.queue_pair_priorities[int(pair)] = priority
        print(
            "  queue pair %d firmware priority %d profile "
            "(%d,%d,%#x,%d,%d)" % (
                int(pair), priority, profile["priority"], profile["unk_2c"],
                profile["unk_30"], profile["unk_38"], profile["prio5"]),
            flush=True,
        )
        return profile

    def graph_arena(self, base, limit=None):
        """Place the submission graph in firmware's own address space.

        The submission graph and the render objects live in different address spaces, and this
        is measured rather than assumed: an item published at an address in the submitting
        context is fetched off the ring and never completed, while the same body at an address
        in firmware's space completes and renders. Render objects are the other way round, in
        the context the work names. So the graph allocator has to hand out firmware addresses,
        which the ordinary context allocator cannot do.
        """
        self._arena_next = base
        self._arena_limit = limit
        self.paired_builder = None
        self.paired_builders = {}

    def prepare_submission_runtime(self, arena_base=G17P_GRAPH_ARENA_BASE,
                                   arena_size=G17P_GRAPH_ARENA_SIZE,
                                   reset_staged=True):
        """Prepare graph allocation and optionally replace the staged seed group."""
        from . import g17p

        if self.runtime_prepared:
            return
        self.graph_arena(arena_base, arena_base + arena_size)
        self._ensure_firmware_range(arena_base, arena_size)
        if not reset_staged:
            self.runtime_prepared = True
            return
        for channel_name in ("TA_0", "3D_0"):
            entry, queue = self.queue_for(channel_name)
            for offset in (g17p.QUEUE_PTR_DONE, g17p.QUEUE_PTR_READ,
                           g17p.QUEUE_PTR_WRITE):
                self._write_dva(
                    queue.pointers_addr + offset, struct.pack("<I", 0))
            # The adopted seed omits this host-owned fixed furniture. Native
            # initial and created queue pointer blocks both carry it before
            # their first work doorbell.
            for offset, value in self.QUEUE_POINTER_FIELDS:
                self._write_dva(
                    queue.pointers_addr + offset, struct.pack("<I", value))
            self._write_dva(
                entry["ring_addr"], bytes(g17p.RING_SLOT_SIZE))
            self._write_dva(
                entry["ring_addr"] + g17p.RING_SLOT_QUEUE_PTR,
                struct.pack("<Q", queue.address))
            self._write_dva(entry["state_addrs"][2], struct.pack("<I", 0))
        self.runtime_prepared = True

    def adopt_completed_staged_group(self, channel_pair=0):
        """Continue pair zero after the cold boot's staged group has completed.

        The boot group is already bound to firmware's record pools and shared
        objects. A live frontend must append after it and retain those objects;
        resetting the queue or constructing a second set changes the lifecycle
        being tested and can make a fetched group retire without rendering.

        ``channel_pair`` selects the TA/3D transport rings carrying pair zero.
        Most cold boots use TA_0/3D_0; the minimum forced-partial opening uses
        TA_2/3D_2 while retaining descriptor/queue pair zero.
        """
        builder = self.paired_builders.get(0)
        if (builder is not None and builder.tiling.array_a is not None
                and builder.shared is not None):
            pools = (builder.tiling.array_a, builder.tiling.array_b)
            shared = tuple(builder.shared)
            source = "frontend-rewritten"
        else:
            pools = tuple(self.bound_submission.get("pools") or ())
            shared = tuple(self.bound_submission.get("shared") or ())
            leaf_pages = dict(self.bound_submission.get("leaf_pages") or {})
            source = "cold-boot"
        if len(pools) != 2 or len(shared) != 2:
            raise G17PUnsupported(
                "the boot artifact must identify two bound record pools and two "
                "bound shared objects before the staged group can be continued")

        channel_pair = int(channel_pair)
        queues = self.muxed_queue_pair(0, channel_pair=channel_pair)
        indices = {kind: queue.indices()
                   for kind, (_entry, queue) in queues.items()}
        heads = {state["write"] for state in indices.values()}
        if len(heads) != 1:
            raise RuntimeError("staged queue write indices disagree: %s" % indices)
        head = heads.pop()
        if not head or head % 3:
            raise RuntimeError(
                "staged queues do not contain whole three-item groups: %s" % indices)
        if any(state["done"] != head or state["read"] != head
               for state in indices.values()):
            raise RuntimeError(
                "staged group has not completed and cannot be adopted: %s" % indices)

        groups = head // 3
        self.prepare_submission_runtime(reset_staged=False)
        builder = self.paired_builder_for(0)
        builder.tiling.use_pools(*pools)
        builder.fragment.use_pools(*pools)
        builder.shared = shared
        if source == "cold-boot":
            required = {
                "primary_index", "secondary_index", "pool_a_slots",
                "pool_b_slots", "shared_slots", "flag",
            }
            missing = required.difference(leaf_pages)
            if missing:
                raise G17PUnsupported(
                    "the boot artifact must identify the bound submission leaf pages: %s" %
                    ", ".join(sorted(missing)))
            builder.leaf_pages = leaf_pages
        self.group_number = groups
        self.queue_pair_submissions[0] = groups
        self.descriptor_pair_submissions[0] = groups
        self.next_scheduler_node = max(self.next_scheduler_node, groups)
        print(
            "G17P continuing after %d staged group(s), %s graph: transport %d, "
            "queues at %d, "
            "bound pools %#x/%#x, shared %#x/%#x" %
            (groups, source, channel_pair, head,
             pools[0], pools[1], shared[0], shared[1]),
            flush=True,
        )

    def execute_rewritten_staged_group(self, cmdbuf):
        """Replace the cold boot's pending payload, execute it, and adopt its head.

        Cold boot publishes the canonical pair-zero ring entries before firmware
        starts and deliberately withholds their doorbell.  A frontend attaching
        to that world must rewrite the objects those entries already name.  It
        must not reset the queue or append a second group before the first head
        has completed.

        This method proves only queue and scheduler retirement.  Its caller must
        compare the submission's target bytes before and after the call.
        """
        queues = self.muxed_queue_pair(0)
        before = {
            kind: queue.indices()
            for kind, (_entry, queue) in queues.items()
        }
        heads = {state["write"] for state in before.values()}
        if len(heads) != 1:
            raise RuntimeError("staged queue write indices disagree: %s" % before)
        head = heads.pop()
        if not head or head % 3:
            raise RuntimeError(
                "staged queues do not contain whole three-item groups: %s" % before)
        if any(state["done"] or state["read"] for state in before.values()):
            raise RuntimeError(
                "staged queues were already consumed; adopt them instead: %s" % before)

        built = self.build_submission(cmdbuf)
        self.space.flush()
        self.prepare_submission_runtime(reset_staged=False)
        rewritten = self.submit_register_pair(
            built["tiling_registers"], built["fragment_registers"],
            built["shared"], built["pools"],
            built["tiling_optional"], built["fragment_optional"],
            context_id=self.primary_execution_context,
            queue_pair=0, notify=False, publish=False,
            parameters=built["parameters"])

        submission = {
            "item_index": rewritten["item_index"],
            "submission_ordinal": rewritten["submission_ordinal"],
            "queue_pair": 0,
            "doorbell_channel": work_doorbell_channel(0),
            "items": rewritten["items"],
        }
        for kind, (entry, queue) in queues.items():
            producer = self.channels.counters(entry)[2]
            submission[kind] = {
                "entry": entry,
                "queue": queue,
                "published": {
                    "producer": producer,
                    "write_after": head,
                },
            }

        self.last_submission = submission
        self.space.flush()
        self.submitter.notify(submission["doorbell_channel"])
        self.wait_pair_completed(submission)
        if self.control_done is not None:
            self.control_done()
            if self.event_pump is not None:
                self.event_pump()
        self.wait_pair_retired(submission)
        self.adopt_completed_staged_group()
        return submission

    def _alloc_graph(self, size, name):
        if getattr(self, "_arena_next", None) is None:
            return self.space.alloc(size, name)[0]
        address = (self._arena_next + 0xf) & ~0xf
        end = address + size
        if self._arena_limit is not None and end > self._arena_limit:
            raise RuntimeError("submission graph arena exhausted at %s (%s needs 0x%x)"
                               % (hex(self._arena_limit), name, size))
        self._ensure_firmware_range(address, size)
        self._write_dva(address, bytes(size))
        self._arena_next = end
        return address

    def paired_builder_for(self, queue_pair=0, descriptor_pair=None):
        from .g17p_backend import G17PPairedWorkBuilder

        if queue_pair not in self.paired_builders:
            builder_pair = (queue_pair if descriptor_pair is None else
                            int(descriptor_pair))
            # Context 2 owns a fresh graph, but its pool/index namespaces start
            # from the same scalar bases as context 1. The context identity is
            # carried by the packed object's +0x0c field, not by adding the
            # queue-pair deltas used by the earlier one-context hypothesis.
            resource_pair = 0 if queue_pair in (2, 3) else builder_pair
            graph_plan = (self.MUX_PAIR1_GRAPH if queue_pair == 1 else
                          self.PARTIAL_PAIR2_GRAPH
                          if queue_pair == 2 and getattr(
                              self, "partial_render_pair2_profile", False)
                          else
                          self.MUX_PAIR2_GRAPH if queue_pair == 2 else
                          self.MUX_PAIR3_GRAPH if queue_pair == 3 else
                          self.MUX_PAIR4_GRAPH
                          if queue_pair == 4 and builder_pair == 3 else None)
            plan = iter(graph_plan) if graph_plan is not None else None
            item_counts = {}

            def alloc(size, name):
                if name in self.ITEM_ARRAYS:
                    key = name
                    local_index = item_counts.get(key, 0)
                    item_counts[key] = local_index + 1
                elif name.startswith("work_descriptor_"):
                    local_index = int(name.rsplit("_", 1)[1])
                    key = ("tiling_descriptor" if size == 0x9c0 else
                           "fragment_descriptor" if size == 0x2240 else None)
                    if key is None:
                        raise RuntimeError(
                            "unknown descriptor size 0x%x" % size)
                else:
                    key = None
                if key is not None:
                    base, stride, capacity = self.ITEM_ARRAYS[key]
                    if size > capacity:
                        raise RuntimeError(
                            "item array %s capacity 0x%x, got 0x%x"
                            % (key, capacity, size))
                    optional_base = self.forced_optional_ordinal_base
                    if (key in ("tiling_optional_item",
                                "fragment_optional_item")
                            and optional_base is not None):
                        ordinal = int(optional_base) + local_index
                    else:
                        ordinal = self.group_number
                    address = base + ordinal * stride
                    self._ensure_firmware_range(address, size)
                    if key in self.DESCRIPTOR_LOW_ARRAYS:
                        self._map_descriptor_alias(key, address, size)
                    return address
                if plan is not None:
                    try:
                        expected_name, address, capacity = next(plan)
                    except StopIteration as exc:
                        raise RuntimeError(
                            "pair-%d graph allocation exceeds the measured layout" %
                            queue_pair) from exc
                    if name != expected_name or size > capacity:
                        raise RuntimeError(
                            "pair-%d graph expected %s <= 0x%x, got %s 0x%x"
                            % (queue_pair, expected_name, capacity, name, size))
                    self._ensure_firmware_range(address, capacity)
                    self._write_dva(address, bytes(capacity))
                    return address
                return self._alloc_graph(size, name)
            self.paired_builders[queue_pair] = G17PPairedWorkBuilder(
                alloc,
                lambda addr, data: self._write_dva(addr, data),
                queue_pair=resource_pair,
            )
        self.paired_builder = self.paired_builders[queue_pair]
        return self.paired_builder

    def create_bo(self, size, name="bo"):
        """Allocate a buffer and return it. Real: a device address and a live mapping."""
        return self.ctx.gobj.new(size, name=name)

    # Objects a submission names that firmware fills, so a driver only has to allocate them.
    # Established by enumerating every address a work register program names and finding these
    # zero in a captured boot.
    # Firmware consumes one 0x5200 parameter-buffer block at a time. The local allocation has
    # eight blocks; completed blocks are recyclable and publication is serialized here, so no
    # live group can be overwritten by a wrapped allocation.
    TILEMAP_BLOCK_STRIDE = 0x5200
    TILEMAP_BLOCKS = 8
    PAIR_RESOURCE_STRIDE = 0x5e0000

    # The pair-one namespace sits elsewhere in the already mapped render-context extent. Do not
    # claim the whole gap here: it contains separately owned objects such as the TPC allocation.
    FIRMWARE_FILLED = (
        ("tilemap", 0x4000 + TILEMAP_BLOCK_STRIDE * TILEMAP_BLOCKS),
        ("tile_parameter_cache", 0x4000),
        ("heapmeta", 0x4000),
        ("ta_status", 0x4000),
        ("fragment_status", 0x4000),
        ("depth_bias_array", 0x4000),
    )

    def _new_render_object(self, name, size):
        objects = getattr(self, "render_objects", None)
        if objects is None:
            objects = self.render_objects = {}
        existing = objects.get(name)
        if existing is not None:
            if existing._size < size:
                raise RuntimeError(
                    "render object %s is %#x bytes, new request needs %#x" %
                    (name, existing._size, size))
            return existing
        layout = getattr(self, "render_layout", None)
        allocator = self.ctx.gobj
        if layout is not None and hasattr(allocator, "new_at"):
            entry = layout[name]
            obj = allocator.new_at(
                entry["dva"],
                size,
                name="g17p_" + name,
                AP=2,
                nG=1,
                UXN=entry["UXN"],
            )
        else:
            obj = allocator.new(size, name="g17p_" + name)
        objects[name] = obj
        return obj

    def submit(self, cmdbuf, attachments=(), context_id=None,
               firmware_priority=None):
        """Translate a command buffer into a paired submission and publish it."""
        if context_id is None and hasattr(self, "space"):
            context_id = self.space.context
        if context_id is not None and (
                not hasattr(self, "space") or context_id != self.space.context):
            self.activate_execution_context(context_id)
        self.acknowledge_report_channels()
        if getattr(self, "reset_render_state", False) and self.group_number:
            cleared = []
            for name, _size in self.FIRMWARE_FILLED:
                obj = self.render_objects.get(name)
                if obj is None:
                    continue
                obj.push(bytes(obj._size))
                cleared.append(name)
            print(
                "G17P reset per-render objects before group %d: %s" % (
                    self.group_number + 1,
                    ", ".join(cleared) if cleared else "none",
                ),
                flush=True,
            )
        queue_pair = self.submission_queue_pair()
        channel_pair = (int(self.forced_channel_pair)
                        if self.forced_channel_pair is not None else 0)
        descriptor_pair = (int(self.forced_descriptor_pair)
                           if self.forced_descriptor_pair is not None else None)
        descriptor_context = (
            int(self.forced_descriptor_context)
            if self.forced_descriptor_context is not None else
            self.primary_execution_context
            if self.logical_vm_switch else context_id)
        if queue_pair in self.destroyed_muxed_queue_pairs:
            raise G17PUnsupported(
                "submission selected destroyed queue pair %d" % queue_pair)
        built = self.build_submission(cmdbuf)
        self.space.flush()
        if queue_pair not in (None, 0):
            if queue_pair not in self.muxed_queue_pairs:
                defer_pair1_graph = bool(
                    queue_pair == 1
                    and self.group_number
                    and self.register_runtime_pair
                    and not self.runtime_pair_registered
                    and self.defer_pair1_graph_until_registration)
                self.create_muxed_queue_pair(
                    queue_pair,
                    {
                        "tiling": built["tiling_optional"],
                        "fragment": built["fragment_optional"],
                    },
                    channel_pair=channel_pair,
                    reserve_graph=not defer_pair1_graph,
                )
                self.space.flush()
                self.u.inst("dsb sy")
                if defer_pair1_graph:
                    print(
                        "  deferred pair-1 submission graph until after "
                        "runtime registration",
                        flush=True,
                    )
        if firmware_priority is not None:
            self.set_muxed_queue_priority(
                0 if queue_pair is None else queue_pair,
                firmware_priority, channel_pair=channel_pair)
        if (queue_pair == 1 and self.group_number and self.register_runtime_pair
                and not self.runtime_pair_registered):
            if self.runtime_pair_register is None:
                raise G17PUnsupported(
                    "runtime submission registration requires in-process cold boot")
            self.runtime_pair_register()
            self.runtime_pair_registered = True
        if (self.group_number >= 2 and self.register_runtime_pair
                and self.group_number not in self.runtime_submission_announced):
            if self.runtime_submission_announce is None:
                raise G17PUnsupported(
                    "later runtime submissions require in-process cold boot")
            self.runtime_submission_announce(self.group_number)
            self.runtime_submission_announced.add(self.group_number)
        # The established attach path builds/remaps the render objects before it
        # claims the cold boot's staged queues. Keep that ordering: queue state is
        # host/firmware synchronization state, not allocator setup.
        if queue_pair == 1 and self.reset_pair_control:
            self._reset_muxed_channel_control(queue_pair)
        if queue_pair == 1 and self.patch_native_prior_control:
            self._patch_native_prior_channel_state()
        self.prepare_submission_runtime()
        submitted = self.submit_register_pair(
            built["tiling_registers"], built["fragment_registers"],
            built["shared"], built["pools"],
            built["tiling_optional"], built["fragment_optional"],
            context_id=descriptor_context,
            queue_pair=queue_pair,
            channel_pair=channel_pair,
            descriptor_pair=descriptor_pair,
            notify=not (self.prefill_second_pair and self.group_number == 0),
            parameters=built["parameters"])
        # Create the command fence at the publication point, before any
        # synchronous wait.  A crash notification during that wait must have
        # a concrete pending fence to terminate and attribute.
        self.pair_fence(submitted)
        if self.prefill_second_pair and submitted["submission_ordinal"] == 0:
            deferred = []
            self.submitter.deferred_producers = deferred
            try:
                second = self.submit_register_pair(
                    built["tiling_registers"], built["fragment_registers"],
                    built["shared"], built["pools"],
                    built["tiling_optional"], built["fragment_optional"],
                    context_id=(self.primary_execution_context
                                if self.logical_vm_switch else context_id),
                    queue_pair=1,
                    notify=False,
                    parameters=built["parameters"],
                )
                self.pair_fence(second)
            finally:
                self.submitter.deferred_producers = None
            self.space.flush()
            self.submitter.notify(submitted["doorbell_channel"])
            for address, value in deferred:
                self.submitter.write(address, value)
            if self.register_runtime_pair:
                if self.runtime_pair_register is None:
                    raise G17PUnsupported(
                        "runtime queue-pair registration requires in-process cold boot")
                self.runtime_pair_register()
                self.runtime_pair_registered = True
            self.submitter.notify(second["doorbell_channel"])

            self.wait_pair_completed(submitted)
            if self.control_done is not None and not self.pair_retired(submitted):
                for _ in range(2):
                    self.control_done()
                    if self.event_pump is not None:
                        self.event_pump()
                    if self.pair_retired(submitted):
                        break
            self.wait_pair_retired(submitted)
            self.wait_pair_completed(second)
            if self.control_done is not None and not self.pair_retired(second):
                self.control_done()
                if self.event_pump is not None:
                    self.event_pump()
            self.wait_pair_retired(second)
            self._complete_native_pair_state(submitted)
            self._complete_native_pair_state(second)
            self.prefilled_second_submission = second
            self.last_submission = second
            return submitted
        # Keep the publication reachable even when a synchronous wait times out.
        # A queue that retired into a populated scheduler list is materially
        # different from one firmware never consumed, and callers need the live
        # queue/job-list addresses to report that distinction.
        self.last_submission = submitted
        if self.deferred_first_submission is not None:
            deferred = self.deferred_first_submission
            self.deferred_first_submission = None
            if self.control_done is not None:
                for _ in range(2):
                    self.control_done()
                    if self.event_pump is not None:
                        self.event_pump()
            self.wait_pair_retired(deferred)
        if (self.pipeline_first_pair
                and submitted["submission_ordinal"] == 0):
            self.deferred_first_submission = submitted
            return submitted
        self.wait_pair_completed(submitted)
        if submitted["submission_fence"].error is not None:
            return submitted
        if self.control_done is not None:
            count = (self.first_control_done_count
                     if submitted["submission_ordinal"] == 0
                     else self.control_done_count)
            print(
                "G17P sending %d control-done message(s) for submission ordinal %d"
                % (count, submitted["submission_ordinal"]),
                flush=True,
            )
            for _ in range(count):
                self.control_done()
                if self.event_pump is not None:
                    self.event_pump()
        if not self.pair_retired(submitted):
            print(
                "G17P scheduler list remains linked after completed queues; "
                "retaining it as diagnostic state",
                flush=True,
            )
        self._complete_native_pair_state(submitted)
        return submitted

    def submit_drm(self, drm_cmdbuf, attachments=(), context_id=None,
                   firmware_priority=None, **supplied):
        """Publish a submission for a DRM command buffer the front end handed down."""
        if context_id is None:
            context_id = self.space.context
        if context_id != self.space.context:
            self.activate_execution_context(context_id)
        color_attachments = [
            attachment for attachment in
            drm_cmdbuf.attachments[:drm_cmdbuf.attachment_count]
            if attachment.type == 0
        ]
        for color in color_attachments:
            obj = next((candidate for candidate in attachments
                        if candidate._addr == color.pointer), None)
            if obj is None:
                raise G17PUnsupported(
                    "G17P color attachment %#x is not a live shim BO" % color.pointer)
            if color.size > obj._size:
                raise G17PUnsupported(
                    "G17P color attachment declares %#x bytes for a %#x-byte BO" %
                    (color.size, obj._size))

        # bind_color_attachment() is a compatibility helper for the original
        # retained one-target workload.  UAPI attachments are optional lifetime
        # hints, not a description from which the kernel reconstructs a
        # framebuffer resource graph.  Multi-target callers supply that graph
        # through their BG/EOT programs and resource BOs, so validating all BOs
        # above is sufficient and patching five one-target records would be
        # actively wrong.
        if len(color_attachments) == 1:
            color = color_attachments[0]
            obj = next(candidate for candidate in attachments
                       if candidate._addr == color.pointer)
            self.bind_color_attachment(
                color.pointer, min(color.size, obj._size),
                drm_cmdbuf.fb_width, drm_cmdbuf.fb_height)
        elif color_attachments:
            print(
                "G17P retaining caller BG/EOT resource graph for %d color "
                "attachment hints" % len(color_attachments),
                flush=True,
            )
        cmdbuf = command_buffer_from_drm(
            drm_cmdbuf, pipeline_base=self.ctx.pipeline_base, **supplied)
        submission_context = context_id
        if self.mirror_registered_vm and context_id != self.primary_execution_context:
            # This firmware world admits one render context. File-private BOs
            # keep disjoint address ranges and are mirrored into its root, but
            # the queue graph and its context-global objects must be updated
            # through the admitted space. A cloned file VM can predate those
            # dynamic graph mappings and is therefore not a valid host view of
            # the shared queue after the first submission.
            self.activate_execution_context(self.primary_execution_context)
            submission_context = self.primary_execution_context
        return self.submit(
            cmdbuf, attachments, context_id=submission_context,
            firmware_priority=firmware_priority)

    def build_submission(self, cmdbuf):
        """Translate a command buffer into everything a submission needs, without publishing.

        Separate from ``submit`` because construction and publication answer different questions
        and, on this part, can only be tested separately: publication needs live firmware, and the
        only submission observed to execute is the one firmware finds as it starts, which has to be
        in place before there is any firmware to ask.

        What this can do now, and could not when it refused outright: the register programs are
        derived from the render dimensions and the addresses of the objects they name, and the
        tiler command stream is emitted from a model. So a caller supplying a target and the
        shader-binding programs gets a real submission built and published.

        What it still cannot do is produce those shader-binding programs. The load and store
        pipelines are compiled code, and nothing in this project compiles shaders, so they have
        to be supplied. That is a narrower gap than the blanket refusal this replaced, and it is
        named rather than hidden behind a generic error.
        """
        g17p_encoder = _sibling("g17p_encoder")
        g17p_render = _sibling("g17p_render")

        width = getattr(cmdbuf, "width", None)
        height = getattr(cmdbuf, "height", None)
        if not width or not height:
            raise G17PUnsupported(
                "a command buffer must carry render dimensions; got %r x %r"
                % (width, height))

        pipelines = {name: getattr(cmdbuf, name, 0)
                     for name in ("store_pipeline", "store_pipeline_bind",
                                  "load_pipeline", "load_pipeline_bind")}
        missing = [name for name, value in pipelines.items()
                   if not value and name.endswith("pipeline")]
        if missing:
            raise G17PUnsupported(
                "the load and store pipelines are compiled shader programs and are not "
                "generated here; supply them on the command buffer. Missing: %s"
                % ", ".join(sorted(missing)))

        encoder_parameters = getattr(cmdbuf, "encoder", None)
        encoder_ptr = getattr(cmdbuf, "encoder_ptr", 0)
        if encoder_parameters is None and not encoder_ptr:
            raise G17PUnsupported(
                "a command buffer must carry the tiler stream: either parameters to build one, "
                "as g17p_encoder.G17PEncoderParameters on .encoder, or the address of a stream "
                "the caller built itself, on .encoder_ptr")

        # Everything the caller had to supply has been checked, so allocate only now: a
        # refusal should not leave objects behind.
        allocated = {}
        context_objects = {
            "tilemap": getattr(cmdbuf, "tilemap", 0),
            "heapmeta": getattr(cmdbuf, "heapmeta", 0),
            "tile_parameter_cache": getattr(cmdbuf, "tpc", 0),
            "ta_status": getattr(cmdbuf, "ta_status", 0),
            "fragment_status": getattr(cmdbuf, "fragment_status", 0),
        }
        for name, size in self.FIRMWARE_FILLED:
            if context_objects.get(name):
                allocated[name] = context_objects[name]
            else:
                allocated[name] = self._new_render_object(
                    name, size
                )._addr

        if encoder_parameters is not None:
            encoder = self._new_render_object(
                "encoder", g17p_encoder.ENCODER_SIZE
            )
            encoder.push(g17p_encoder.build_encoder(encoder_parameters))
            encoder_address = encoder._addr
        else:
            # The caller built the stream itself, which is what a DRM caller does: the encoder is
            # userspace's to write. Nothing is allocated for it and its contents are not read, so
            # a stream this backend could not have generated still reaches hardware.
            encoder_address = encoder_ptr

        context_base = getattr(
            self, "render_context_base", self.ctx.pipeline_base
        )
        transport_pair = self.submission_queue_pair()
        if transport_pair is None:
            transport_pair = getattr(self, "queue_pair", 0)
        queue_pair = (int(self.forced_descriptor_pair)
                      if self.forced_descriptor_pair is not None else
                      transport_pair)
        descriptor_context = (
            int(self.forced_descriptor_context)
            if self.forced_descriptor_context is not None else None)
        # Context-2 descriptors identify their queue grids as pairs 2/3, but
        # native register arrays restart the cycle, record-index, and low
        # status-address namespaces at pair zero.
        register_pair = (
            0 if transport_pair in (2, 3) and descriptor_context == 2
            else queue_pair)
        descriptor_submissions = getattr(
            self, "descriptor_pair_submissions", {})
        queue_item_index = descriptor_submissions.get(
            queue_pair,
            getattr(self, "queue_pair_submissions", {}).get(transport_pair, 0)
            if queue_pair == transport_pair else 0)
        # Native forced-partial work is the first command in a fresh register
        # generation even when the transport queue and descriptor graph have a
        # later identity.  Keep this as a hardware discriminator until the
        # positive direct-source run establishes that partial programs are the
        # semantic selector for the restart.
        base_register_namespace = (
            os.getenv("G17P_BASE_RENDER_REGISTER_NAMESPACE") == "1")
        if base_register_namespace:
            register_pair = 0
            queue_item_index = 0
        native_item_fields = os.getenv("G17P_NATIVE_ITEM_FIELDS") == "1"
        native_pair_registers = (
            native_item_fields
            or os.getenv("G17P_NATIVE_PAIR_REGISTERS") == "1")
        native_cycle_registers = (
            native_pair_registers
            or os.getenv("G17P_NATIVE_CYCLE_REGISTERS") == "1")
        native_record_index_register = (
            native_pair_registers
            or os.getenv("G17P_NATIVE_RECORD_INDEX_REGISTER") == "1")
        native_status_registers = (
            native_item_fields
            or os.getenv("G17P_NATIVE_STATUS_REGISTERS") == "1")
        # Hardware discriminator for the forced-partial status namespace.
        # This is intentionally independent of cycle/record-index selection:
        # the two low status registers were the only parameter differences
        # between an executing hybrid command and today's source command.
        base_status_namespace = (
            os.getenv("G17P_BASE_STATUS_REGISTER_NAMESPACE") == "1")
        local_item_registers = (
            os.getenv("G17P_LOCAL_ITEM_REGISTERS") == "1")
        parameters = g17p_render.G17PRenderParameters(
            width=width, height=height,
            context_base=context_base,
            tilemap=allocated["tilemap"],
            heapmeta=allocated["heapmeta"],
            tpc=allocated["tile_parameter_cache"],
            deflake_1=getattr(cmdbuf, "deflake_1", 0),
            deflake_2=getattr(cmdbuf, "deflake_2", 0),
            deflake_3=getattr(cmdbuf, "deflake_3", 0),
            encoder=encoder_address,
            ta_status=allocated["ta_status"],
            fragment_status=allocated["fragment_status"],
            timestamp_a=getattr(
                cmdbuf, "timestamp_a", g17p_render.RENDER_TIMESTAMP_A),
            timestamp_b=getattr(
                cmdbuf, "timestamp_b", g17p_render.RENDER_TIMESTAMP_B),
            ta_timestamp_end=getattr(cmdbuf, "ta_timestamp_end", 0),
            fragment_timestamp_start=getattr(
                cmdbuf, "fragment_timestamp_start",
                getattr(cmdbuf, "timestamp_a", g17p_render.RENDER_TIMESTAMP_A)),
            fragment_timestamp_end=getattr(
                cmdbuf, "fragment_timestamp_end",
                getattr(cmdbuf, "timestamp_b", g17p_render.RENDER_TIMESTAMP_B)),
            ta_user_timestamp_start=getattr(
                cmdbuf, "ta_user_timestamp_start", 0),
            ta_user_timestamp_end=getattr(
                cmdbuf, "ta_user_timestamp_end", 0),
            fragment_user_timestamp_start=getattr(
                cmdbuf, "fragment_user_timestamp_start", 0),
            fragment_user_timestamp_end=getattr(
                cmdbuf, "fragment_user_timestamp_end", 0),
            lifecycle_ordinal=(
                0 if base_register_namespace else self.group_number
                if os.getenv("G17P_NATIVE_LIFECYCLE_FIELDS") == "1"
                else 0
            ),
            queue_pair=register_pair,
            queue_item_index=queue_item_index,
            status_queue_pair=(
                0 if base_status_namespace or base_register_namespace else None),
            status_item_index=(
                0 if base_status_namespace or base_register_namespace else None),
            native_cycle_registers=native_cycle_registers,
            native_record_index_register=native_record_index_register,
            native_pair_registers=native_pair_registers,
            native_status_registers=native_status_registers,
            local_item_registers=local_item_registers,
            native_item_fields=native_item_fields,
            layers=getattr(cmdbuf, "layers", 1),
            utile_width=getattr(cmdbuf, "utile_width", 32),
            utile_height=getattr(cmdbuf, "utile_height", 32),
            samples=getattr(cmdbuf, "samples", 1),
            sample_size=getattr(cmdbuf, "sample_size", 0),
            usc_exec_base=getattr(
                cmdbuf, "usc_exec_base", self.ctx.pipeline_base),
            depth_bias_array=getattr(
                cmdbuf, "depth_bias_array", allocated["depth_bias_array"]),
            scissor_array=getattr(cmdbuf, "scissor_array", 0),
            occlusion_query_base=getattr(
                cmdbuf, "occlusion_query_base", 0),
            depth_buffer=getattr(cmdbuf, "depth_buffer", 0),
            depth_aux_buffer=getattr(cmdbuf, "depth_aux_buffer", 0),
            depth_stride=getattr(cmdbuf, "depth_stride", 0),
            depth_aux_stride=getattr(cmdbuf, "depth_aux_stride", 0),
            stencil_buffer=getattr(cmdbuf, "stencil_buffer", 0),
            stencil_aux_buffer=getattr(cmdbuf, "stencil_aux_buffer", 0),
            stencil_stride=getattr(cmdbuf, "stencil_stride", 0),
            stencil_aux_stride=getattr(cmdbuf, "stencil_aux_stride", 0),
            depth_flags=getattr(cmdbuf, "depth_flags", 0),
            depth_dimensions=getattr(cmdbuf, "depth_dimensions", 0),
            depth_clear_value_bits=getattr(
                cmdbuf, "depth_clear_value_bits", 0x3f800000),
            stencil_clear_value=getattr(cmdbuf, "stencil_clear_value", 0),
            merge_upper_x_bits=getattr(cmdbuf, "merge_upper_x_bits", 0),
            merge_upper_y_bits=getattr(cmdbuf, "merge_upper_y_bits", 0),
            partial_load_pipeline_bind=getattr(
                cmdbuf, "partial_load_pipeline_bind", 0),
            partial_load_pipeline=getattr(
                cmdbuf, "partial_load_pipeline", 0),
            partial_store_pipeline_bind=getattr(
                cmdbuf, "partial_store_pipeline_bind", 0),
            partial_store_pipeline=getattr(
                cmdbuf, "partial_store_pipeline", 0),
            sampler_array=getattr(cmdbuf, "sampler_array", 0),
            sampler_count=getattr(cmdbuf, "sampler_count", 0),
            process_empty_tiles=getattr(
                cmdbuf, "process_empty_tiles", True),
            emit_uapi_fields=getattr(cmdbuf, "emit_uapi_fields", False),
            aux_fb=getattr(cmdbuf, "aux_fb", 0),
            aux_fb_flags=getattr(cmdbuf, "aux_fb_flags", 0xc001),
            **pipelines,
            **{name: getattr(cmdbuf, name)
               for name in ("utile_config", "multisample_control",
                            "ppp_control", "tib_blocks", "tile_config")
               if hasattr(cmdbuf, name)})

        # This page is shared by serialized submissions, but its tile limits
        # and viewport transform belong to the current framebuffer.
        viewport_page = parameters.deflake_3 & ~(
            g17p_render.RENDER_OBJECT_PAGE - 1)
        self._write_dva(
            viewport_page,
            g17p_render.build_viewport(parameters.width, parameters.height),
        )

        return {
            "tiling_registers": g17p_render.build_tiling_registers(parameters),
            "fragment_registers": g17p_render.build_fragment_registers(parameters),
            "shared": getattr(cmdbuf, "shared", None),
            "pools": getattr(cmdbuf, "pools", None),
            "tiling_optional": getattr(cmdbuf, "tiling_optional", None),
            "fragment_optional": getattr(cmdbuf, "fragment_optional", None),
            "parameters": parameters,
            "allocated": allocated,
            "encoder": encoder_address,
        }

    def submit_registers(self, channel_name, kind, items, shared, pools):
        """Publish a submission whose items carry the given register arrays.

        ``items`` is a sequence of ``(registers, support_a, support_b)``. This is the path a
        replay uses, and the one the gates cover: the bodies are generated by the model rather
        than copied, and checked byte for byte against captured submissions.
        """
        entry, queue = self.queue_for(channel_name)
        builder = self.builder_for(kind)
        if builder.array_a is None and not pools:
            # Build pools, shared objects and their leaf pages the way the boot does, which is what
            # "build_shared_objects first" is asking for. A caller that supplies pools is naming
            # ones that already exist and keeps the older path below.
            builder.build_submission_graph()
        elif builder.array_a is None:
            if len(pools) != 3:
                raise G17PUnsupported(
                    "the record pools must be three values, both pool bases and the shared "
                    "slot; got %d" % len(pools))
            builder.build_pools(*pools)
        addresses = []
        for index, (registers, support_a, support_b) in enumerate(items):
            addresses.append(builder.item(index, shared, registers, support_a, support_b))
        flat = [address for triple in addresses for address in triple]
        self.group_number += 1
        published = self.submitter.publish(entry, queue, flat, self.group_number)
        return {"entry": entry, "queue": queue, "published": published}

    # A working host advances two global counters for every group. The exact steps are
    # workload-dependent (0x46 and 5 were measured between two consecutive groups); what matters
    # here is that successive groups carry distinct, increasing values, so fixed steps are used.
    GLOBAL_STAMP_STEP = 0x46
    GLOBAL_COUNTER_STEP = 5

    def _apply_group_identity(self, pair, group_index):
        """Give a group an identity of its own: stamp, counter and ordinal.

        The stamp is the one with a stated mechanism. Firmware copies it into the group's pool-A
        record when the group completes, so a second group carrying the first group's stamp
        presents as something that has already finished; taking it off the ring and marking it
        done without running it is exactly what a scheduler would then do.

        The ordinal fields are written absolutely because their rules are exact. The stamp and
        counter fields are advanced from whatever the builder wrote, because only their step is
        known and not their origin.
        """
        if not group_index:
            return

        def bump32(address, delta):
            value = struct.unpack("<I", self._read_dva(address, 4))[0]
            self._write_dva(address, struct.pack("<I", (value + delta) & 0xffffffff))

        def put32(address, value):
            self._write_dva(address, struct.pack("<I", value & 0xffffffff))

        tiling, fragment = pair["tiling"][0], pair["fragment"][0]
        stamp_delta = self.GLOBAL_STAMP_STEP * group_index
        counter_delta = self.GLOBAL_COUNTER_STEP * group_index

        # The global stamp, carried three times in each descriptor and once shifted.
        for offset in (0x34c, 0x358, 0x364):
            bump32(tiling + offset, stamp_delta)
        for offset in (0x434, 0x440, 0x44c):
            bump32(fragment + offset, stamp_delta)
        bump32(tiling + 0x8cc, stamp_delta << 16)

        # The second global counter, same shape.
        for offset in (0x350, 0x35c, 0x368):
            bump32(tiling + offset, counter_delta)
        for offset in (0x438, 0x444, 0x450):
            bump32(fragment + offset, counter_delta)
        bump32(tiling + 0x86c, counter_delta << 16)

        # The ordinal, encoded eight different ways in the tiling descriptor and once in the
        # fragment one. A working host's first group is ordinal 1.
        ordinal = group_index + 1
        put32(tiling + 0x7a0, ordinal * 0x100)
        put32(tiling + 0x7a8, ordinal)
        put32(tiling + 0x7b0, ordinal * 0x101)
        put32(tiling + 0x8b4, (ordinal << 24) | 0xffff)
        put32(tiling + 0x8c4, ordinal << 16)
        put32(tiling + 0x8c8, ordinal << 24)
        put32(tiling + 0x8d4, (ordinal - 1) << 16)
        bump32(tiling + 0x944, 0x4000 * group_index)
        put32(fragment + 0x90, ordinal)

        print("  group identity: ordinal %d, stamp +%#x, counter +%#x"
              % (ordinal, stamp_delta, counter_delta), flush=True)

    def _advance_tilemap_block(self, pair, group_index, pair_index=0):
        """Point a group at its own parameter-buffer block.

        A working host moves this block on by 0x5200 for every group across the eight-block
        allocation. This path waits for each group before publishing the next, so a completed
        block can be recycled when the finite allocation wraps. Reusing the immediately previous
        group's block leaves the tiler looking at a consumed tile list and does no work.

        The delta is added to whatever the builder wrote, so each field keeps its own form: some
        of these hold the block address, some the block plus 0x5000, and one is a full 64-bit
        device address rather than a context offset.
        """
        use_pair_namespace = (
            self.pair_resource_namespace or
            (self.pair_resource_namespace_after_first and group_index > 0) or
            (self.native_b2_full_descriptor_shape
             and pair_index == 1 and group_index == 1)
        )
        pair_step = (self.PAIR_RESOURCE_STRIDE * pair_index
                     if use_pair_namespace else 0)
        if not group_index and not pair_step:
            return
        block_index = group_index % self.TILEMAP_BLOCKS
        step = self.TILEMAP_BLOCK_STRIDE * block_index + pair_step
        tiling, fragment = pair["tiling"][0], pair["fragment"][0]

        if group_index >= self.TILEMAP_BLOCKS:
            # These are firmware output blocks. Once the serialized submission
            # owning a block has retired, restore the same zero prestate used at
            # allocation before handing the block to another group.
            tilemap_offset = struct.unpack(
                "<I", self._read_dva(tiling + 0x7c, 4))[0]
            block = self.render_context_base + tilemap_offset + step
            self._write_dva(block, bytes(self.TILEMAP_BLOCK_STRIDE))
            print(
                "  reset completed parameter-buffer block %d at %#x" %
                (block_index, block),
                flush=True,
            )

        for offset in (0x7c, 0x88, 0xa0, 0xac, 0x148, 0x154):
            address = tiling + offset
            value = struct.unpack("<I", self._read_dva(address, 4))[0]
            self._write_dva(address, struct.pack("<I", (value + step) & 0xffffffff))

        for offset in (0x17c, 0x314, 0x320):
            address = fragment + offset
            value = struct.unpack("<I", self._read_dva(address, 4))[0]
            self._write_dva(address, struct.pack("<I", (value + step) & 0xffffffff))

        address = fragment + 0x40
        value = struct.unpack("<Q", self._read_dva(address, 8))[0]
        self._write_dva(address, struct.pack("<Q", value + step))

        # TPC is pair-local but not item-local in the measured native series.
        if pair_step:
            for offset in (0x94, 0x780):
                address = tiling + offset
                value = struct.unpack("<I", self._read_dva(address, 4))[0]
                self._write_dva(
                    address, struct.pack("<I", (value + pair_step) & 0xffffffff))

        if block_index != group_index:
            print(
                "  recycled completed parameter-buffer block %d from logical item %d" %
                (block_index, group_index),
                flush=True,
            )
        print("  parameter-buffer resources advanced by %#x" % step, flush=True)

    def report_pair_progress(self, pair, label=""):
        """Firmware-written completion counters, which the host never touches."""
        try:
            objt = struct.unpack("<Q", self._read_dva(pair["tiling"][0] + 0x20, 8))[0]
            words = struct.unpack("<6I", self._read_dva(objt, 24))
        except Exception as exc:                                    # noqa: BLE001
            print("  progress unreadable: %s" % exc, flush=True)
            return
        print("  objT %#x %s+0x00=%d +0x04=%d +0x08=%d +0x0c=%#x +0x14=%d"
              % (objt, label, words[0], words[1], words[2], words[3], words[5]), flush=True)

    def _write_current_job_records(self, pair, pair_index, item_index,
                                   ta_queue, fragment_queue):
        """Publish the fixed TA/3D current-job records before the work doorbell."""
        address = 0xfffffc20c07d0000
        current = (
            pair_index,
            item_index + 1,
            pair["tiling"][0],
            ta_queue.address,
            pair["fragment"][0],
            fragment_queue.address,
        )
        published = current
        if self.lag_current_job_records and self.previous_current_job_record is not None:
            published = self.previous_current_job_record
        self.previous_current_job_record = current
        (record_pair, sequence, tiling_descriptor, tiling_queue,
         fragment_descriptor, fragment_queue_address) = published
        pair_bits = record_pair << 10
        records = (
            (0, 0x0000000000000013, 0x20,
             tiling_descriptor, tiling_queue),
            (0x40, 0x0100000000000223, 0x82,
             fragment_descriptor, fragment_queue_address),
        )
        for offset, base_header, second, descriptor, queue in records:
            header = base_header | pair_bits | (sequence << 48)
            self._write_dva(address + offset, struct.pack("<Q", header))
            self._write_dva(address + offset + 0x08, struct.pack("<Q", second))
            self._write_dva(address + offset + 0x30, struct.pack("<Q", descriptor))
            self._write_dva(address + offset + 0x38, struct.pack("<Q", queue))
        print(
            "  current-job records: pair %d sequence %d TA desc %#x queue %#x; "
            "3D desc %#x queue %#x%s" %
            (record_pair, sequence, tiling_descriptor, tiling_queue,
             fragment_descriptor, fragment_queue_address,
             " (previous publication)" if published != current else ""),
            flush=True,
        )

    def _apply_per_group_resources(self, pair, group_index, pair_index):
        """Advance the per-group resources a working host never reuses.

        Two independent things, both of which present as "firmware retires the group and the
        accelerator writes nothing", which is why they are applied together.

        Before publishing a new pair, the native host releases the previously published pair's
        parameter-buffer object by writing all-ones. The current pair still holds its literal
        pair index while its group is outstanding.

        The deltas are applied to whatever the builder wrote rather than to an absolute base, so
        the relationships inside each descriptor are preserved whatever form the field takes.
        """
        def u32(address):
            return struct.unpack("<I", self._read_dva(address, 4))[0]

        def u64(address):
            return struct.unpack("<Q", self._read_dva(address, 8))[0]

        def put32(address, value):
            self._write_dva(address, struct.pack("<I", value & 0xffffffff))

        tiling, fragment = pair["tiling"][0], pair["fragment"][0]

        if self.native_leaf_lifecycle and not self.native_leaf_publication:
            builder = self.paired_builders.get(pair_index)
            pages = getattr(builder, "leaf_pages", None) if builder else None
            if pages is not None:
                shared_slots = pages["shared_slots"]
                flag = pages["flag"]
                put32(shared_slots + 0x04, 0x20)
                if group_index:
                    put32(shared_slots + 0x40, 0x13)
                put32(shared_slots + 0x60, 1)
                put32(flag, group_index + 1)
                print(
                    "  native leaf lifecycle: shared +0x04=0x20 "
                    "+0x40=%#x +0x60=1, flag=%d" %
                    (0x13 if group_index else 0, group_index + 1),
                    flush=True,
                )

        if self.tile_heap_marker:
            if self.native_pb_release_previous and self.last_published_pair is not None:
                previous_tiling = self.last_published_pair["tiling"][0]
                previous_objt = u64(previous_tiling + 0x20)
                previous_marker = u32(previous_objt + 0x0c)
                put32(previous_objt + 0x0c, 0xffffffff)
                print("  released previous parameter-buffer object %#x -> 0xffffffff "
                      "(objT %#x)" % (previous_marker, previous_objt), flush=True)
            objt = u64(tiling + 0x20)
            marker = u32(objt + 0x0c)
            if marker != 0xffffffff:
                put32(objt + 0x0c, 0xffffffff)
            put32(objt + 0x0c, pair_index)
            print("  tile-heap marker %#x -> %d (objT %#x)" %
                  (marker, pair_index, objt), flush=True)

        if self.own_pair_dispatch_count:
            # Firmware advances +0x04 and +0x14 on this object when a group completes, and in
            # every captured snapshot +0x00 holds the same value. In our world firmware moves
            # +0x04 and +0x14 to one after the first group while +0x00 stays zero, so +0x00 is
            # not firmware's: the host owns it and we have never written it. Its captured value
            # is the number of groups already dispatched on the pair.
            objt = u64(tiling + 0x20)
            dispatch_count = (
                group_index + 1
                if pair_index in (2, 3) and (
                    self.forced_descriptor_context == 2
                    or (pair_index == 2 and getattr(
                        self, "partial_render_pair2_profile", False)))
                else group_index)
            put32(objt + 0x00, dispatch_count)
            print("  pair dispatch count +0x00 = %d" % dispatch_count, flush=True)

        if self.native_fragment_2174 and pair_index == 1 and group_index == 1:
            put32(fragment + 0x2174, 1)
            print("  native B2 fragment +0x2174 = 1", flush=True)

        if self.native_b2_scalars and pair_index == 1 and group_index == 1:
            # Host-authored scalar values that change together at native B2. Timestamp and
            # completion fields are intentionally excluded; +0x420 also varies with the
            # workload and is not part of this publication-state experiment.
            for offset, value in (
                    (0x070, 0),
                    (0x338, 0xfe),
                    (0x93c, 0x98600001)):
                put32(tiling + offset, value)
            put32(fragment + 0x338, 0x10000)
            put32(fragment + 0x3a8, u32(fragment + 0x3a8) & ~0x20)
            for offset, value in (
                    (0x6ac, 0xa00),
                    (0x6b0, 0x3af00),
                    (0x6b8, 0x57780),
                    (0x1f58, 0x10000),
                    (0x2174, 1),
                    (0x21d8, 0xb980)):
                put32(fragment + offset, value)
            print("  native B2 descriptor scalar family applied", flush=True)

        if (self.native_b2_full_descriptor_shape
                and pair_index == 1 and group_index == 1):
            for offset, value in (
                    (0x070, 0),
                    (0x338, 0xfe),
                    (0x93c, 0x98600001)):
                put32(tiling + offset, value)
            for offset, value in (
                    (0x1a0, 0x0000c000),
                    (0x32c, 0xb0000000),
                    (0x330, 0x00000004),
                    (0x338, 0x00010000),
                    (0x3a8, 0x05e4ba00),
                    (0x6a0, 0x01dddc00),
                    (0x6a4, 0x008c0200),
                    (0x6a8, 0x01e16c00),
                    (0x6ac, 0x00000a00),
                    (0x6b0, 0x0003af00),
                    (0x6b4, 0x008c0202),
                    (0x6b8, 0x00057780),
                    (0x6bc, 0x00000a02),
                    (0x1d2c, 0),
                    (0x1f40, 0x0000c000),
                    (0x1f58, 0x00010000),
                    (0x1fa0, 0x00000100),
                    (0x2174, 1),
                    (0x21d8, 0x0000b980)):
                put32(fragment + offset, value)
            print(
                "  native B2 full descriptor-control shape applied",
                flush=True,
            )

    def _complete_native_leaf_publication(self, submission):
        """Preserve the pair-one leaf state observed after its first retirement."""
        if (not self.native_leaf_publication
                or submission.get(
                    "descriptor_pair", submission.get("queue_pair")) != 1
                or submission.get(
                    "descriptor_item_index", submission.get("item_index")) != 0):
            return
        # Descriptor pair one can be multiplexed over the original grid-0/1
        # transport and graph builder. Its retained leaf pages belong to that
        # builder, not necessarily to builder key one.
        builder = self.paired_builders.get(submission.get("queue_pair", 1))
        pages = getattr(builder, "leaf_pages", None) if builder else None
        if pages is None:
            raise RuntimeError("pair-one leaf pages are unavailable after retirement")
        self._write_dva(
            pages["shared_slots"] + 0x40, struct.pack("<I", 0x13))
        print(
            "  native leaf retirement: pair-one shared +0x40=0x13",
            flush=True,
        )

    def _complete_native_pair_state(self, submission):
        """Apply selectable native state observed after pair-one retirement."""
        self._complete_native_leaf_publication(submission)
        if (not self.patch_pair1_pool_b_completion
                or submission.get(
                    "descriptor_pair", submission.get("queue_pair")) != 1
                or submission.get(
                    "descriptor_item_index", submission.get("item_index")) != 0):
            return
        descriptor = submission["items"]["tiling"][0]
        record = struct.unpack(
            "<Q", self._read_dva(descriptor + 0x28, 8))[0]
        self._write_dva(record + 0x10, struct.pack("<I", 0x13))
        self._write_dva(record + 0x48, struct.pack("<I", 0x13))
        print(
            "  native pair-one Pool-B retirement: %#x +0x10/+0x48=0x13" %
            record,
            flush=True,
        )

    def _patch_native_queue_completion_counters(self):
        """Install the four queue +0x94 values captured after native A2 completed."""
        values = {
            0: {"tiling": 0x193, "fragment": 0x16794},
            1: {"tiling": 0x4df, "fragment": 0x3d78},
        }
        for pair_index, pair_values in values.items():
            queues = self.muxed_queue_pair(pair_index)
            for kind, value in pair_values.items():
                queue = queues[kind][1]
                self._write_dva(queue.address + 0x94, struct.pack("<I", value))
        print("  native post-A2 queue +0x94 completion counters applied", flush=True)

    def _apply_scheduler_node(self, pair, node_id, pair_index, item_index):
        """Write the per-group scheduler-node state a working host writes before its doorbell.

        A working host never republishes a group: each one takes the next record of the two pools
        and *populates* it. Our builder only ever chose which record the descriptor points at and
        left the record itself zero, which makes a node that can be linked but carries no job for
        the scheduler. That is the shape of the failure being chased: firmware takes the item off
        the ring, marks it done and runs nothing.

        The node id is the field that makes a group distinct. A second group carrying id 0 names an
        id that already completed, so a scheduler that keys on it has nothing to do.

        The record addresses are read back out of the descriptor rather than recomputed, so this
        cannot disagree with whatever record the builder selected.
        """
        def u32(address):
            return struct.unpack("<I", self._read_dva(address, 4))[0]

        def u64(address):
            return struct.unpack("<Q", self._read_dva(address, 8))[0]

        def put32(address, value):
            self._write_dva(address, struct.pack("<I", value & 0xffffffff))

        tiling, fragment = pair["tiling"][0], pair["fragment"][0]
        record_a = u64(tiling + 0x10)
        record_b = u64(tiling + 0x28)

        # Pool A record: the node id, and the constant that gives the scheduler a job to run.
        # +0x0c and +0x24 belong to firmware, so these are 32-bit writes, not one 64-bit store.
        put32(record_a + 0x08, node_id)
        put32(record_a + 0x10, 0x50)

        # The record's own +0x00 back-pointer names its slot in the low array, which carries
        # twice the number of groups referencing the node.
        slot = u64(record_a + 0x00)
        if not self.native_scheduler_publication:
            # The phased final-26.6 path has already published this exact slot
            # as 0 -> 1 -> 2 while building the fragment and tiling halves.
            # Writing 1 here afterwards undid its tiling phase and was isolated
            # physically as a completed-without-drawing partial render.  The
            # older single-phase path still installs its established ready
            # value directly.
            put32(slot, 2)

        # Pool B record.
        put32(record_b + 0x4c, 1)

        # The descriptors' copies of the node id. Fragment +0x48 is a constant and is left alone.
        put32(tiling + 0x48, node_id)
        for offset in (0x370, 0x37c, 0x388):
            put32(tiling + offset, 0x100 | node_id)
        for offset in (0x470, 0x47c):
            put32(fragment + offset, 0x100 | node_id)

        # The descriptors' mirrors of the pool B record they now name. One
        # target-witnessed pair-one run retained the builder's pair-zero base
        # mirrors here while naming a pair-one Pool-B record. Keep that exact
        # five-byte discriminator independently selectable for hardware tests.
        # Pair zero keeps the base mirrors across its measured series.  The
        # created pair is asymmetric: its first item also carries the base
        # values, but later items mirror the Pool-B record they select.
        retain_base_mirrors = (
            self.keep_base_descriptor_mirrors
            and (pair_index == 0 or item_index == 0)
        )
        if retain_base_mirrors:
            print("  retained base Pool-B descriptor mirrors", flush=True)
        else:
            b00, b28 = u32(record_b + 0x00), u32(record_b + 0x28)
            for offset in (0x310, 0x31c):
                put32(tiling + offset, b28)
            put32(tiling + 0x328, b00 | 1)
            put32(fragment + 0x464, b28)

        print("  scheduler node %d: poolA %#x poolB %#x" % (node_id, record_a, record_b),
              flush=True)

    def _apply_reserved_scheduler_node(self, builder, node_id,
                                       pair_index, item_index):
        """Materialize the otherwise unreferenced node between pair-one jobs.

        Native pair one advances Pool A by two records per item. The intervening
        record is not named by either descriptor, but still carries the globally
        reserved scheduler ordinal and the normal 0x50 host marker before B2.
        """
        if (not self.materialize_reserved_scheduler_node
                or pair_index != 1 or item_index == 0):
            return
        from . import g17p_submission as submission

        record_index = 2 * item_index - 1
        record = builder.tiling.array_a + record_index * submission.ARRAY_A_STRIDE
        reserved_node_id = node_id - 2
        self._write_dva(record + 0x08, struct.pack("<I", reserved_node_id))
        self._write_dva(
            record + submission.ARRAY_A_FIRST_MARKER_OFFSET,
            struct.pack("<I", submission.ARRAY_A_FIRST_MARKER),
        )
        print(
            "  reserved scheduler node %d: poolA %#x" %
            (reserved_node_id, record),
            flush=True,
        )

    def submit_register_pair(
        self,
        tiling_registers,
        fragment_registers,
        shared,
        pools,
        tiling_optional,
        fragment_optional,
        context_id=SHIM_CONTEXT,
        queue_pair=None,
        channel_pair=0,
        descriptor_pair=None,
        notify=True,
        publish=True,
        parameters=None,
    ):
        """Build, stage, and notify one paired TA/fragment work unit.

        The optional-item mappings contain the four pointer arguments accepted by
        ``build_optional_item``. Descriptor objects and event storage are allocated
        here; register values and the objects they name remain caller-owned.
        """
        from . import g17p_submission as submission
        from .g17p_backend import G17PWorkBuilder

        if queue_pair is None:
            # Preserve the old explicit channel-pair experiment. The production
            # scheduler passes a queue pair and multiplexes it over channel pair 0.
            pair = getattr(self, "queue_pair", 0)
            ta_entry, ta_queue = self.queue_for("TA_%d" % pair)
            fragment_entry, fragment_queue = self.queue_for("3D_%d" % pair)
        else:
            queues = self.muxed_queue_pair(queue_pair, channel_pair)
            ta_entry, ta_queue = queues["tiling"]
            fragment_entry, fragment_queue = queues["fragment"]
        pair_index = (queue_pair if queue_pair is not None
                      else getattr(self, "queue_pair", 0))
        if (self.native_partial_opening_queue and pair_index == 0
                and self.group_number == 0):
            self._apply_native_partial_opening_queue({
                "tiling": (ta_entry, ta_queue),
                "fragment": (fragment_entry, fragment_queue),
            })
        descriptor_pair_index = (pair_index if descriptor_pair is None else
                                 int(descriptor_pair))
        builder = self.paired_builder_for(pair_index, descriptor_pair_index)
        built_graph = False
        if builder.tiling.array_a is None:
            if pools and pair_index == 0:
                builder.build_pools(*pools)
            else:
                # No pools named means build the whole submission graph, pools, shared objects and
                # their leaf pages, which is what the boot does and what the item builder's
                # "build_shared_objects first" is asking for.
                builder.build_submission_graph()
                built_graph = True
        partial_pair2 = bool(
            pair_index == 2
            and getattr(self, "partial_render_pair2_profile", False))
        independent_runtime_graph = (
            built_graph and pair_index != 0
            and not (
                pair_index == 1
                and (self.share_bound_record_pools
                     or self.share_bound_submission_state)
            )
        )
        if independent_runtime_graph:
            # Most independently owned runtime graphs observed so far use the
            # secondary-index leaf as their descriptor cleanup/control page.
            # The exact partial pair is the counterexample: its optional items
            # name a distinct shared-control object at c08d0000 while its
            # secondary index is c08e0000.  The physically positive replay and
            # native descriptor tails both bind the former.
            control_page = builder.leaf_pages["secondary_index"]
            if partial_pair2:
                pair_pointers = self.muxed_queue_pointer_sets.get(pair_index)
                if pair_pointers is None:
                    raise RuntimeError(
                        "partial descriptor control has no created-pair "
                        "optional mappings"
                    )
                tiling_control = int(
                    pair_pointers["tiling"]["shared_control"])
                fragment_control = int(
                    pair_pointers["fragment"]["shared_control"])
                if tiling_control != fragment_control:
                    raise RuntimeError(
                        "partial descriptor control bindings disagree: "
                        "%#x != %#x" % (tiling_control, fragment_control)
                    )
                control_page = tiling_control
            control = builder.bind_runtime_control_page(control_page)
            print(
                "  pair %d binds independent descriptor control page %#x" %
                (pair_index, control),
                flush=True,
            )
        graph_context2 = bool(
            pair_index in (2, 3) and (context_id == 2 or partial_pair2))
        if built_graph and graph_context2:
            # Context 2 owns a smaller, fresh index graph while its pool scalar
            # namespace restarts from the base values.
            leaves = submission.build_context2_submission_leaf_pages()
            for name, body in leaves.items():
                self._write_dva(builder.leaf_pages[name], body)
            packed = submission.build_context2_shared_object((
                builder.leaf_pages["primary_index"],
                builder.leaf_pages["secondary_index"],
                builder.leaf_pages["shared_slots"],
                builder.leaf_pages["flag"],
            ), context_id=2 if partial_pair2 else context_id)
            self._write_dva(builder.shared[0], packed)

        # Lifecycle publication clears the high status records while building
        # the descriptor. Created pairs therefore need their high backing and
        # render-context aliases before builder.item() invokes the phase hook.
        self._map_pair_status_aliases(descriptor_pair_index)

        item_index = self.queue_pair_submissions.get(pair_index, 0)
        descriptor_item_index = self.descriptor_pair_submissions.get(
            descriptor_pair_index,
            item_index if descriptor_pair_index == pair_index else 0)
        graph_item_base = self.pair_graph_item_bases.get(
            descriptor_pair_index, 0)
        graph_item_index = descriptor_item_index - graph_item_base
        if graph_item_index < 0:
            raise RuntimeError(
                "descriptor pair %d item %d precedes graph base %d" %
                (descriptor_pair_index, descriptor_item_index,
                 graph_item_base))
        resource_item_index = self.pair_resource_submissions.get(
            descriptor_pair_index, graph_item_index)
        if (descriptor_pair_index != pair_index
                or descriptor_item_index != item_index
                or graph_item_base):
            print(
                "  transport pair %d item %d uses descriptor pair %d "
                "item %d, graph-local item %d" %
                (pair_index, item_index, descriptor_pair_index,
                 descriptor_item_index, graph_item_index),
                flush=True,
            )

        pool_record_indices = None
        if self.forced_pool_record_indices is not None:
            # Record ownership and record selection are independent.  Pair 1
            # can retain pair 0's already-bound pools while selecting an
            # explicitly measured A/B record within them.  Treating these as
            # mutually exclusive silently selected the same record numbers
            # from pair 1's private, unbound graph instead.
            if descriptor_pair_index == 1 and self.share_bound_record_pools:
                primary_builder = self.paired_builders.get(0)
                if (primary_builder is None
                        or primary_builder.tiling.array_a is None):
                    raise RuntimeError(
                        "pair 1 cannot retain pair 0 record pools before "
                        "pair 0 is built")
                builder.tiling.use_pools(
                    primary_builder.tiling.array_a,
                    primary_builder.tiling.array_b)
                builder.fragment.use_pools(
                    primary_builder.fragment.array_a,
                    primary_builder.fragment.array_b)
            raw_pool_record_indices = tuple(
                int(value) for value in self.forced_pool_record_indices)
            if len(raw_pool_record_indices) != 2:
                raise ValueError("forced pool record selection needs A and B")
            pool_record_indices = submission.wrap_pool_record_indices(
                *raw_pool_record_indices)
            print(
                "  forced pair %d pool records %d/%d from pools %#x/%#x" %
                ((pair_index,) + pool_record_indices + (
                    builder.tiling.array_a, builder.tiling.array_b)),
                flush=True,
            )
        elif descriptor_pair_index == 1 and self.share_bound_record_pools:
            primary_builder = self.paired_builders.get(0)
            if primary_builder is None or primary_builder.tiling.array_a is None:
                raise RuntimeError(
                    "pair 1 cannot retain pair 0 record pools before pair 0 is built")
            builder.tiling.use_pools(
                primary_builder.tiling.array_a, primary_builder.tiling.array_b)
            builder.fragment.use_pools(
                primary_builder.fragment.array_a, primary_builder.fragment.array_b)
            raw_pool_record_indices = (
                2 * self.group_number,
                self.group_number + self.pool_b_logical_bias,
            )
            pool_record_indices = submission.wrap_pool_record_indices(
                *raw_pool_record_indices)
            print(
                "  descriptor pair %d retains bound record pools %#x/%#x "
                "at records %d/%d" %
                (descriptor_pair_index, builder.tiling.array_a,
                 builder.tiling.array_b,
                 pool_record_indices[0], pool_record_indices[1]),
                flush=True,
            )
            if pool_record_indices != raw_pool_record_indices:
                print(
                    "  recycled completed pool records from logical %d/%d" %
                    raw_pool_record_indices,
                    flush=True,
                )
        elif graph_context2:
            # Context 2 holds Pool A record zero across its queue lifetime;
            # Pool B advances once per item.
            pool_record_indices = (0, graph_item_index)

        context2_pair = graph_context2
        # The event counter is local to a queue pair. A host's first groups on
        # grids 0/1 and 2/3 both carry 0x100 even though the latter is the
        # second global submission.
        group_number = item_index + 1
        if (self.native_primary_publication
                and pair_index == 1 and item_index == 1):
            self._patch_native_b2_primary_publication()
        pair_optional = self.muxed_queue_pointer_sets.get(pair_index)
        if pair_optional is not None:
            tiling_optional = pair_optional["tiling"]
            fragment_optional = pair_optional["fragment"]
        if descriptor_pair_index != pair_index:
            descriptor_optional = self.muxed_queue_pointer_sets.get(
                descriptor_pair_index)
            if descriptor_optional is None:
                if descriptor_pair_index != 1:
                    raise RuntimeError(
                        "descriptor pair %d has no optional-pointer state" %
                        descriptor_pair_index)
                # The opening fixed-grid lifecycle uses logical descriptor
                # pair one without creating its otherwise dormant queues. Its
                # context identity and channel-control record are nevertheless
                # explicit in the native record and in the independently
                # created pair-one positive control.
                descriptor_optional = {
                    kind: {
                        "channel_control": self.CHANNEL_CONTROL_BASE,
                        "context_id": 1,
                    }
                    for kind in ("tiling", "fragment")
                }
            mixed_optional = {}
            for kind, transport in (
                    ("tiling", tiling_optional),
                    ("fragment", fragment_optional)):
                transport = dict(transport)
                descriptor = descriptor_optional[kind]
                # Native's second group remains on queue grids 0/1 and uses
                # those queues' scratch/context item 1.  Its scheduler identity
                # and channel-control record, however, belong to descriptor
                # context 1.  Offset 0x56 is the transport-context half of the
                # otherwise paired context fields, so preserve pair zero there.
                transport_context = transport.get("context_id")
                if transport_context is None:
                    transport_context = pair_index
                descriptor_context = descriptor.get("context_id")
                if descriptor_context is None:
                    descriptor_context = descriptor_pair_index
                transport["channel_control"] = descriptor["channel_control"]
                transport["context_id"] = descriptor_context
                # None selects the legacy scheduler encoding: it derives the
                # +0x5e identity from context without writing the separate
                # +0x1e/+0x46 class fields. Native's fixed-grid second record
                # has exactly that split.
                transport["scheduler_class"] = descriptor.get(
                    "scheduler_class")
                overrides = dict(transport.get("u16_overrides", {}))
                overrides[0x56] = int(transport_context)
                transport["u16_overrides"] = overrides
                mixed_optional[kind] = transport
            tiling_optional = mixed_optional["tiling"]
            fragment_optional = mixed_optional["fragment"]
            print(
                "  transport pair %d optional item uses descriptor context %d "
                "and channel control %#x" %
                (pair_index, descriptor_pair_index,
                 int(tiling_optional["channel_control"])),
                flush=True,
            )
        if self.native_partial_opening_queue and pair_index == 0:
            # All 36 opening renders belong to the same transport ownership
            # domain even while their descriptor/resource namespace alternates.
            # Descriptor identity must not redirect the optional item to a
            # different persistent scheduler object.
            native_optional = []
            for values in (tiling_optional, fragment_optional):
                values = dict(values)
                values["shared_control"] = (
                    self.NATIVE_PARTIAL_OPENING_SHARED_CONTROL)
                values["channel_control"] = self.CHANNEL_CONTROL_BASE
                values["context_id"] = self.primary_execution_context
                values["uuid"] = self.NATIVE_PARTIAL_OPENING_UUID
                native_optional.append(values)
            tiling_optional, fragment_optional = native_optional
        pair_shared = shared if pair_index == 0 else None
        publication_builder = builder
        if descriptor_pair_index == 1 and self.share_bound_submission_state:
            primary_builder = self.paired_builders.get(0)
            if primary_builder is None or primary_builder.shared is None:
                raise RuntimeError(
                    "pair 1 cannot retain pair 0 submission state before pair 0 is built")
            pair_shared = primary_builder.shared
            publication_builder = primary_builder
            print(
                "  descriptor pair %d retains bound packed/zero objects %#x/%#x" %
                (descriptor_pair_index, pair_shared[0], pair_shared[1]),
                flush=True,
            )
        phase_hook = None
        publication_lifecycle = None
        inner_address = None
        if (self.native_scheduler_publication
                or self.native_shared_inner_sequence
                or self.native_leaf_publication
                or self.native_status_publication):
            # Use the paired builder's finite-pool selection verbatim.  The
            # 36-render native opening crosses Pool A's 35-record boundary at
            # logical item 18 (A36 -> A1); an unwrapped lifecycle address reads
            # beyond Pool A even though the descriptor correctly names A1.
            phase_records = submission.paired_item_pool_record_indices(
                graph_item_index, record_indices=pool_record_indices)
            phase_record_a = (
                builder.tiling.array_a
                + phase_records[0] * submission.ARRAY_A_STRIDE)
            phase_slot = struct.unpack(
                "<Q", self._read_dva(phase_record_a, 8))[0]
            phase_current = struct.unpack(
                "<I", self._read_dva(phase_slot, 4))[0]
            inner_current = None
            inner_target = None
            # Only the initial/runtime pair families name the nested sequence
            # object at optional +0x36. Context-2 and context-4 records use the
            # same field for their pair-local index page instead.
            if (self.native_shared_inner_sequence
                    and pair_index in (0, 1)):
                shared_control_address = int(tiling_optional["shared_control"])
                inner_address = struct.unpack(
                    "<Q", self._read_dva(shared_control_address + 0x4c, 8))[0]
                if not inner_address:
                    raise RuntimeError(
                        "shared-control object %#x has no inner pointer" %
                        shared_control_address)
                inner_current = struct.unpack(
                    "<I", self._read_dva(inner_address, 4))[0]
                inner_target = 2 * (self.group_number + 1)
                if inner_current > inner_target:
                    raise RuntimeError(
                        "shared-control inner counter %#x exceeds target %#x" %
                        (inner_current, inner_target))
            leaf_shared = None
            leaf_flag = None
            leaf_shared_count = None
            if self.native_leaf_publication:
                pages = getattr(publication_builder, "leaf_pages", None)
                if pages is None:
                    raise RuntimeError(
                        "native leaf publication requires pair leaf pages")
                leaf_shared = pages["shared_slots"]
                leaf_flag = pages["flag"]
                leaf_shared_count = struct.unpack(
                    "<I", self._read_dva(leaf_shared, 4))[0]
            status_addresses = None
            if self.native_status_publication:
                status_addresses = {
                    kind: G17PWorkBuilder.PAIR_STATUS_BASES[kind][
                        descriptor_pair_index]
                    + graph_item_index * 0x40
                    for kind in ("tiling", "fragment")
                }

            def apply_lifecycle_phase(phase):
                if (self.native_leaf_publication and phase == "before"
                        and not context2_pair):
                    self._write_dva(
                        leaf_shared + 0x04,
                        struct.pack("<I", leaf_shared_count))
                    self._write_dva(
                        leaf_shared + 0x60, struct.pack("<I", 1))
                if self.native_scheduler_publication:
                    if context2_pair:
                        values = {
                            "before": phase_current,
                            "fragment": phase_current + 1,
                            "tiling": phase_current + 2,
                        }
                    else:
                        values = {"before": 0, "fragment": 1, "tiling": 2}
                    self._write_dva(
                        phase_slot, struct.pack("<I", values[phase]))
                if (inner_address is not None
                        and inner_current < inner_target
                        and phase in ("fragment", "tiling")):
                    value = (inner_target - 1 if phase == "fragment"
                             else inner_target)
                    self._write_dva(
                        inner_address, struct.pack("<I", value))
                if self.native_status_publication and phase == "fragment":
                    self._write_dva(
                        status_addresses["fragment"], bytes(0x40))
                if self.native_leaf_publication and phase == "fragment":
                    self._write_dva(
                        leaf_flag, struct.pack(
                            "<I", resource_item_index +
                            (2 if context2_pair else 1)))
                if self.native_status_publication and phase == "fragment":
                    self._write_dva(
                        0xfffffc2000024c68, struct.pack("<QQ", 0, 0))
                if self.native_status_publication and phase == "tiling":
                    self._write_dva(
                        status_addresses["tiling"], bytes(0x40))

            if self.native_split_lifecycle_publication:
                publication_lifecycle = apply_lifecycle_phase

                def phase_hook(phase):
                    if phase == "before":
                        apply_lifecycle_phase(phase)
            else:
                phase_hook = apply_lifecycle_phase

        # Self pointers are low aliases of the actual allocation.  Derive them
        # from placement rather than assuming placement always equals the work
        # ordinal; the default path remains byte-identical.
        tiling_slot = self.group_number
        builder.tiling.low_alias = {
            "tiling": self.DESCRIPTOR_LOW_ARRAYS["tiling_descriptor"]
            + tiling_slot * self.ITEM_ARRAYS["tiling_descriptor"][1]
        }
        builder.fragment.low_alias = {
            "fragment": self.DESCRIPTOR_LOW_ARRAYS["fragment_descriptor"]
            + self.group_number * self.ITEM_ARRAYS["fragment_descriptor"][1]
        }
        effective_shared = pair_shared if pair_shared is not None else builder.shared
        if effective_shared is None:
            raise RuntimeError("paired submission has no packed shared object")
        primary_alias = self._map_submission_primary_index_alias(
            effective_shared[0])
        print(
            "  primary-index dual alias high=%#x low=%#x pa=%#x" % (
                primary_alias["high"], primary_alias["low"],
                primary_alias["pa"]),
            flush=True,
        )
        pair = builder.item(
            graph_item_index,
            pair_shared,
            tiling_registers,
            fragment_registers,
            tiling_optional,
            fragment_optional,
            context_id,
            submission_ordinal=self.group_number,
            queue_pair=descriptor_pair_index,
            record_indices=pool_record_indices,
            parameters=parameters,
            lifecycle_phase=phase_hook,
            optional_submission_ordinal=(
                None if self.forced_optional_ordinal_base is None else
                int(self.forced_optional_ordinal_base) + item_index),
            queue_grid_pair=(ta_queue.grid_index, fragment_queue.grid_index),
            optional_item_index=item_index,
        )
        if self.omit_optional_item:
            pair = {
                kind: (items[0], items[2])
                for kind, items in pair.items()
            }
            print("  publishing descriptor/event without optional item", flush=True)
        if self.native_scheduler_publication:
            if context2_pair:
                scheduler_sequence = "%#x -> %#x -> %#x" % (
                    phase_current, phase_current + 1, phase_current + 2)
            else:
                scheduler_sequence = "0 -> 1 -> 2"
            print(
                "  scheduler publication slot %#x: %s" %
                (phase_slot, scheduler_sequence),
                flush=True,
            )
        if inner_address is not None and not context2_pair:
            print(
                "  shared-control inner sequence %#x -> %#x" %
                (inner_current, inner_target),
                flush=True,
            )
        if self.native_leaf_publication:
            if context2_pair:
                print(
                    "  native context-2 leaf publication: retain shared state, "
                    "flag=%d after fragment" % (resource_item_index + 2),
                    flush=True,
                )
            else:
                print(
                    "  native leaf publication: shared +0x04=0x20 +0x60=1 "
                    "before fragment, flag=%d after fragment" %
                    (graph_item_index + 1),
                    flush=True,
                )
        if self.native_status_publication:
            print(
                "  native status publication: fragment %#x, global +0xc68/+0xc70, "
                "tiling %#x cleared" %
                (status_addresses["fragment"], status_addresses["tiling"]),
                flush=True,
            )

        reuse_key = (channel_pair, pair_index)
        canonical = self.reusable_queue_items.get(reuse_key)
        in_place = bool(
            self.reuse_queue_items
            and canonical is not None
            and not self.append_reused_queue_items
        )
        if self.reuse_queue_items:
            if canonical is None:
                self.reusable_queue_items[reuse_key] = {
                    kind: tuple(pair[kind]) for kind in ("tiling", "fragment")
                }
            else:
                from .g17p_backend import G17PWorkBuilder

                # The queue ring keeps naming the first descriptor, optional
                # item and event item. Refresh those objects from the newly
                # built group, which still names fresh scheduler-pool records.
                # Descriptor self pointers use the low alias of the canonical
                # array slot rather than the temporary source slot.
                for kind in ("tiling", "fragment"):
                    source = pair[kind]
                    target = canonical[kind]
                    descriptor_kind = "%s_descriptor" % kind
                    body = G17PWorkBuilder.BODY_STRIDE[kind]
                    self._write_dva(
                        target[0], self._read_dva(source[0], body))
                    low_base = self.DESCRIPTOR_LOW_ARRAYS[descriptor_kind]
                    high_base = self.ITEM_ARRAYS[descriptor_kind][0]
                    target_low = low_base + (target[0] - high_base)
                    for offset, value, role in G17PWorkBuilder.TAIL_POINTERS[kind]:
                        if role == "self":
                            self._write_dva(
                                target[0] + offset,
                                struct.pack("<Q", target_low + value - low_base))
                    self._write_dva(
                        target[1], self._read_dva(source[1], 0xc0))
                    self._write_dva(
                        target[2], self._read_dva(source[2], 0x40))
                pair = {kind: tuple(canonical[kind])
                        for kind in ("tiling", "fragment")}

        # Every UAT context needs the low aliases through which its queue's
        # descriptor self-pointers resolve. The first context gets these while
        # the canonical arrays are allocated; later cloned contexts may have
        # been created before that allocation and therefore install them here.
        for kind in ("tiling", "fragment"):
            self._map_descriptor_alias(
                "%s_descriptor" % kind, pair[kind][0], 1)
        if partial_pair2 and self.forced_scheduler_node is None:
            # The partial graph owns a local scheduler sequence like the
            # earlier context-2 graph, but its descriptor/render identity is
            # context 3.  Its first item is node zero with 0x300 stamps; later
            # items advance in the same reserved-node sequence while retaining
            # the context-3 stamp namespace.  Hardwiring zero here made a
            # replay-shaped logical item one internally inconsistent.
            node_id = submission.descriptor_work_ordinal(graph_item_index)
            record_a = struct.unpack(
                "<Q", self._read_dva(pair["tiling"][0] + 0x10, 8))[0]
            self._write_dva(record_a + 0x08, struct.pack("<I", node_id))
            self._write_dva(
                pair["tiling"][0] + 0x48, struct.pack("<I", node_id))
            for offset in (0x370, 0x37c, 0x388):
                self._write_dva(
                    pair["tiling"][0] + offset,
                    struct.pack("<I", 0x300 + node_id))
            for offset in (0x470, 0x47c):
                self._write_dva(
                    pair["fragment"][0] + offset,
                    struct.pack("<I", 0x300 + node_id))
        elif graph_context2 and self.forced_scheduler_node is None:
            # Context-2 work has a local scheduler namespace. Across two
            # consecutive native pair-2 submissions its Pool-A record remains
            # zero, descriptor work stays zero, and every stamp remains 0x200.
            record_a = struct.unpack(
                "<Q", self._read_dva(pair["tiling"][0] + 0x10, 8))[0]
            self._write_dva(record_a + 0x08, struct.pack("<I", 0))
            self._write_dva(pair["tiling"][0] + 0x48, struct.pack("<I", 0))
            for offset in (0x370, 0x37c, 0x388):
                self._write_dva(
                    pair["tiling"][0] + offset, struct.pack("<I", 0x200))
            for offset in (0x470, 0x47c):
                self._write_dva(
                    pair["fragment"][0] + offset, struct.pack("<I", 0x200))
        elif self.scheduler_node_state:
            # This identity is global across queue pairs but is not a dense
            # counter. Native reserves one value outside the descriptor stream
            # after every two submissions: 0, 1, 3, 4, 6, 7, ... . The builder
            # already uses this rule; do not overwrite it with 0, 1, 2, ... .
            node_id = (
                submission.descriptor_work_ordinal(self.group_number)
                if self.forced_scheduler_node is None else
                int(self.forced_scheduler_node)
            )
            self.next_scheduler_node = node_id + 1
            self._apply_reserved_scheduler_node(
                builder, node_id, descriptor_pair_index, graph_item_index)
            self._apply_scheduler_node(
                pair, node_id, descriptor_pair_index, graph_item_index)
        self._apply_per_group_resources(
            pair, resource_item_index, descriptor_pair_index)
        if (self.native_queue_completion_counters
                and pair_index == 1 and item_index == 1):
            self._patch_native_queue_completion_counters()
        if (self.native_b2_control_state
                and pair_index == 1 and item_index == 1):
            self._patch_native_b2_control_state()
        if self.advance_tilemap_block:
            self._advance_tilemap_block(
                pair, resource_item_index, descriptor_pair_index)
        if self.group_identity_fields:
            self._apply_group_identity(pair, item_index)
        self.report_pair_progress(pair, "pre-doorbell ")
        self.last_published_pair = pair

        # Firmware consumes one 0x200-stride record in the high queue-context
        # page per queue-local item. The first record starts at +0x200; native
        # pair-zero work writes its second record at +0x400 before publishing
        # global ordinal two. Updating only the first record retires that later
        # group but does not execute it.
        for kind, queue, optional in (
                ("tiling", ta_queue, tiling_optional),
                ("fragment", fragment_queue, fragment_optional)):
            descriptor = pair[kind][0]
            context = optional["firmware_scratch"]
            # In-place publication refreshes the canonical first group, so its
            # queue-context locator remains item zero even though the logical
            # submission ordinal advances. Appended groups use their own slot.
            if in_place:
                context_item_index = 0
            elif "queue_context_index_base" in optional:
                context_item_index = (
                    int(optional["queue_context_index_base"]) + item_index)
            else:
                context_item_index = item_index
            context_offset = (
                submission.QUEUE_CONTEXT_ITEM_BASE
                + context_item_index * submission.QUEUE_CONTEXT_ITEM_STRIDE)
            # The queue-context record describes the transport queue/grid. It
            # therefore carries grids 6/7 and context 2 for pair-3 work.
            queue_context = (
                int(self.forced_queue_context)
                if self.forced_queue_context is not None else context_id)
            context_item = submission.build_queue_context_item(
                kind, descriptor, queue.address, pair=pair_index,
                item_index=context_item_index, context_id=queue_context,
                grid_index=queue.grid_index,
                locator_context_id=context_id)
            context_capacity = (
                self.MUX_PAIR1_CONTEXT_PAGES * submission.FIRMWARE_PAGE_SIZE)
            if context_offset + len(context_item) > context_capacity:
                raise RuntimeError(
                    "queue context object has no item slot %d" % context_item_index)
            self._write_dva(
                context + context_offset, context_item)

        if not publish:
            return {
                "item_index": item_index,
                "descriptor_item_index": descriptor_item_index,
                "submission_ordinal": self.group_number,
                "queue_pair": pair_index,
                "descriptor_pair": descriptor_pair_index,
                "context_id": context_id,
                "items": pair,
            }

        # Publish either the canonical three-item group or the newly appended
        # group. Native captured traffic advances the head for appended groups.
        writes = (ta_queue.indices()["write"], fragment_queue.indices()["write"])
        slots = (self.channels.next_free_slot(ta_entry),
                 self.channels.next_free_slot(fragment_entry))
        if writes[0] != writes[1]:
            raise RuntimeError(
                "paired queue write indices disagree: tiling %d, fragment %d" % writes)
        if slots[0] != slots[1]:
            raise RuntimeError(
                "paired channel slots disagree: tiling %d, fragment %d" % slots)
        # Bit 24 in the outer slot describes the queue group named by the
        # advertised head, not whether this is the queue's first publication.
        # Native in-place slot 1 still advertises head three with the bit set.
        advertised_head = (writes[0] if in_place
                           else writes[0] + len(pair["tiling"]))
        first_group = advertised_head == len(pair["tiling"])
        split_hook = self.split_pair_publication_hook
        deferred_producers = None
        split_publication = (
            split_hook is not None or publication_lifecycle is not None)
        if split_publication:
            if self.submitter.deferred_producers is not None:
                raise RuntimeError(
                    "split pair publication conflicts with deferred producers")
            deferred_producers = []
            self.submitter.deferred_producers = deferred_producers
        try:
            ta_published = self.submitter.stage(
                ta_entry, ta_queue, pair["tiling"], group_number,
                slot=slots[0], first_submit=first_group, kind="tiling",
                in_place=in_place, announce=False,
                event_counter=0x302 if context_id == 4 else None,
                event_counter_low=(
                    2 if context_id == 2 else 0))
            fragment_published = self.submitter.stage(
                fragment_entry, fragment_queue, pair["fragment"], group_number,
                slot=slots[1], first_submit=first_group, kind="fragment",
                in_place=in_place, announce=False,
                event_counter=0x102 if context_id == 4 else None,
                event_counter_low=(
                    2 if context_id == 2 else 0))
        finally:
            if split_publication:
                self.submitter.deferred_producers = None
        if split_publication:
            if len(deferred_producers) != 2:
                raise RuntimeError(
                    "split pair publication staged %d producer writes" %
                    len(deferred_producers))
            order = tuple(self.split_pair_publication_order)
            if set(order) != {"tiling", "fragment"} or len(order) != 2:
                raise RuntimeError(
                    "split pair publication order must name tiling and fragment")
            producer_for = {
                "tiling": deferred_producers[0],
                "fragment": deferred_producers[1],
            }
            for position, kind in enumerate(order):
                if publication_lifecycle is not None:
                    publication_lifecycle(kind)
                    self.u.inst("dsb sy")
                self.submitter.write(*producer_for[kind])
                self.u.inst("dsb sy")
                if position == 0 and split_hook is not None:
                    self.split_pair_publication_hook = None
                    split_hook(self, pair_index)
            print(
                "  split publication: %s -> lifecycle/control -> %s" % order,
                flush=True,
            )
        # Building descriptor aliases edits the low-root tables after pair creation.
        # Reassert and verify the created pair's upper-root objects at the last
        # possible point before its producer and doorbell become visible.
        self._map_muxed_context_aliases(pair_index)
        self._map_pair_status_aliases(descriptor_pair_index)
        submission_ordinal = self.group_number
        if self.runtime_current_job_records:
            self._write_current_job_records(
                pair, pair_index, item_index, ta_queue, fragment_queue)
        if self.pre_notify_hook is not None:
            self.pre_notify_hook(self, pair_index)
        if notify:
            if self.publish_dsb:
                self.u.inst("dsb sy")
            self.submitter.notify(work_doorbell_channel(channel_pair))
        self.group_number += 1
        self.queue_pair_submissions[pair_index] = item_index + 1
        self.descriptor_pair_submissions[descriptor_pair_index] = (
            descriptor_item_index + 1)
        self.pair_resource_submissions[descriptor_pair_index] = (
            resource_item_index + 1)
        return {
            "item_index": item_index,
            "descriptor_item_index": descriptor_item_index,
            "submission_ordinal": submission_ordinal,
            "queue_pair": pair_index,
            "descriptor_pair": descriptor_pair_index,
            "context_id": context_id,
            "doorbell_channel": work_doorbell_channel(channel_pair),
            "tiling": {
                "entry": ta_entry,
                "queue": ta_queue,
                "published": ta_published,
            },
            "fragment": {
                "entry": fragment_entry,
                "queue": fragment_queue,
                "published": fragment_published,
            },
            "items": pair,
        }

    def completed(self, submission):
        return self.submitter.completed(
            submission["entry"], submission["queue"], submission["published"])

    def pair_completed(self, submission):
        return all(
            self.completed(submission[kind])
            for kind in ("tiling", "fragment")
        )

    def pair_queue_completed(self, submission):
        """True once both queue done indices cover their published entries.

        Channel counters are useful publication diagnostics but are not a
        completion fence: a live shim submission rendered after its queue done
        indices advanced even though a later attach read zero channel counters.
        """
        return all(
            submission[kind]["queue"].indices()["done"] >=
            submission[kind]["published"]["write_after"]
            for kind in ("tiling", "fragment")
        )

    def pair_fence(self, submission, name=None, metadata=None):
        """Return the single UAPI-visible fence for one TA/fragment command."""
        existing = submission.get("submission_fence")
        if existing is not None:
            if metadata:
                existing.metadata.update(metadata)
            return existing

        from .g17p_backend import G17PQueueFence

        command_fences = []
        for kind in ("tiling", "fragment"):
            state = submission[kind]
            command_fences.append(G17PQueueFence(
                self.submitter,
                state["entry"],
                state["queue"],
                state["published"],
                name="%s %s" % (name or "render", kind),
            ))
        attribution = {
            "context_id": submission.get("context_id"),
            "queue_pair": submission.get("queue_pair"),
            "submission_ordinal": submission.get("submission_ordinal"),
        }
        attribution.update(metadata or {})
        fence = self.fence_tracker.track(
            command_fences,
            name=name or "render submission",
            metadata=attribution,
        )
        submission["submission_fence"] = fence
        return fence

    def fail_queue_fences(self, queue_pair, error):
        """Terminate pending submissions owned by one destroyed queue pair."""
        return self.fence_tracker.fail_matching(
            error, reason="queue-teardown", queue_pair=int(queue_pair))

    def fail_context_fences(self, context_id, error):
        """Terminate pending submissions owned by one removed execution VM."""
        return self.fence_tracker.fail_matching(
            error, reason="vm-teardown", context_id=int(context_id))

    def fail_all_fences(self, error):
        """Terminate every pending submission after a fatal device failure."""
        return self.fence_tracker.fail_all(error, reason="device-lost")

    def pair_retired(self, submission):
        """True when firmware retired the queues and drained the scheduler job.

        This is a firmware-lifecycle witness, not proof that TA/3D executed. A
        render target or another accelerator-produced object must establish
        semantic execution.
        """
        from . import g17p

        if not self.pair_queue_completed(submission):
            return False
        seen = set()
        for kind in ("tiling", "fragment"):
            queue = submission[kind]["queue"]
            if queue.job_list_addr in seen:
                continue
            seen.add(queue.job_list_addr)
            head = g17p.parse_job_list(
                self._read_dva(queue.job_list_addr, g17p.JOB_LIST_SIZE),
                own_address=queue.job_list_addr)
            if not head.get("empty"):
                return False
        return True

    def wait_pair_completed(self, submission, timeout=2.0):
        """Wait until both queue entries complete, before acknowledging them."""
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            fence = submission.get("submission_fence")
            if fence is not None and fence.error is not None:
                return submission
            completed = (self.pair_completed(submission)
                         if self.wait_channel_completion
                         else self.pair_queue_completed(submission))
            if completed:
                return submission
            if self.event_pump is not None:
                self.event_pump()
            time.sleep(0.001)
        state = {
            kind: {
                "queue": submission[kind]["queue"].indices(),
                "channel": self.channels.counters(submission[kind]["entry"]),
                "producer": submission[kind]["published"]["producer"],
            }
            for kind in ("tiling", "fragment")
        }
        raise TimeoutError("G17P submission was not consumed: %r" % state)

    def wait_pair_retired(self, submission, timeout=2.0):
        """Wait for queue and scheduler retirement, with a bounded poll.

        Retirement is not evidence that TA/3D rendered. Only a change in the
        target pages assigned to this submission establishes rendering.
        """
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.pair_retired(submission):
                return submission
            time.sleep(0.001)
        state = {
            kind: submission[kind]["queue"].indices()
            for kind in ("tiling", "fragment")
        }
        raise TimeoutError("G17P submission did not retire: %r" % state)

    def quiesce_submission(self, submission, semantic_complete=False,
                           semantic_failed=False):
        """Release serialized scheduler state after a proven terminal result.

        Queue completion alone is not execution evidence.  Once the caller has
        either observed the expected target/output or classified the completed
        submission as failed from an unchanged/invalid output, however, a linked
        job list is stale host-visible state and may be reset while both queues
        are idle.  Extra control-done messages do not perform this transition.
        """
        if semantic_complete and semantic_failed:
            raise ValueError(
                "a submission cannot be both semantically complete and failed")
        self.wait_pair_completed(submission)
        if self.pair_retired(submission):
            return 0
        if not (semantic_complete or semantic_failed):
            raise G17PUnsupported(
                "linked scheduler state may only be reset after the output "
                "establishes success or failure")

        from . import g17p

        reset = 0
        seen = set()
        for kind in ("tiling", "fragment"):
            address = submission[kind]["queue"].job_list_addr
            if address in seen:
                continue
            seen.add(address)
            self._write_dva(address, g17p.build_job_list(address))
            self._clean_dva_range(address, g17p.JOB_LIST_SIZE)
            reset += 1
        self.u.inst("dsb sy")
        if not self.pair_retired(submission):
            raise RuntimeError("scheduler job list did not reset after completed work")
        return reset

    def rebuild_registered_submission_graph(self, pair):
        """Regenerate a quiesced pair's registered graph at the same addresses."""
        pair = int(pair)
        builder = self.paired_builders.get(pair)
        if builder is None:
            raise G17PUnsupported(
                "queue pair %d has no registered submission graph" % pair)
        rebuilt = builder.rebuild_submission_graph()
        self.space.flush()
        self.u.inst("dsb sy")
        print(
            "G17P rebuilt registered pair %d graph at pools %#x/%#x "
            "shared %#x/%#x" % (
                pair,
                rebuilt["pools"][0],
                rebuilt["pools"][1],
                rebuilt["shared"][0],
                rebuilt["shared"][1],
            ),
            flush=True,
        )
        return rebuilt
