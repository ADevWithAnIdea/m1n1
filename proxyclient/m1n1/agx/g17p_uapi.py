# SPDX-License-Identifier: MIT
"""Exact userspace layouts and command parsing for the modern Asahi UAPI."""

import ctypes
from dataclasses import dataclass


u8 = ctypes.c_uint8
u16 = ctypes.c_uint16
u32 = ctypes.c_uint32
u64 = ctypes.c_uint64

DRM_ASAHI_FEATURE_SOFT_FAULTS = 1 << 0
DRM_ASAHI_MAX_CLUSTERS = 64
DRM_ASAHI_MAX_COMMANDS = 64
DRM_ASAHI_MAX_ATTACHMENTS = 16

DRM_ASAHI_BIND_UNBIND = 1 << 0
DRM_ASAHI_BIND_READ = 1 << 1
DRM_ASAHI_BIND_WRITE = 1 << 2
DRM_ASAHI_BIND_SINGLE_PAGE = 1 << 3

DRM_ASAHI_GEM_WRITEBACK = 1 << 0
DRM_ASAHI_GEM_VM_PRIVATE = 1 << 1

DRM_ASAHI_BIND_OBJECT_OP_BIND = 0
DRM_ASAHI_BIND_OBJECT_OP_UNBIND = 1
DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS = 1 << 0

DRM_ASAHI_CMD_RENDER = 0
DRM_ASAHI_CMD_COMPUTE = 1
DRM_ASAHI_SET_VERTEX_ATTACHMENTS = 2
DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS = 3
DRM_ASAHI_SET_COMPUTE_ATTACHMENTS = 4
DRM_ASAHI_BARRIER_NONE = 0xffff

DRM_ASAHI_RENDER_VERTEX_SCRATCH = 1 << 0
DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES = 1 << 1
DRM_ASAHI_RENDER_NO_VERTEX_CLUSTERING = 1 << 2
DRM_ASAHI_RENDER_DBIAS_IS_INT = 1 << 18

DRM_ASAHI_SYNC_SYNCOBJ = 0
DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ = 1


class UAPIStructure(ctypes.LittleEndianStructure):
    @classmethod
    def from_bytes(cls, data, extensible=False):
        data = bytes(data)
        size = ctypes.sizeof(cls)
        if not extensible and len(data) != size:
            raise ValueError(
                "%s requires %#x bytes, got %#x" %
                (cls.__name__, size, len(data)))
        if extensible and len(data) > size and any(data[size:]):
            raise ValueError("unknown %s fields must be zero" % cls.__name__)
        return cls.from_buffer_copy(data[:size].ljust(size, b"\0"))

    def to_bytes(self):
        return bytes(memoryview(self))


class drm_asahi_params_global(UAPIStructure):
    _fields_ = [
        ("features", u64),
        ("gpu_generation", u32),
        ("gpu_variant", u32),
        ("gpu_revision", u32),
        ("chip_id", u32),
        ("num_dies", u32),
        ("num_clusters_total", u32),
        ("num_cores_per_cluster", u32),
        ("max_frequency_khz", u32),
        ("core_masks", u64 * DRM_ASAHI_MAX_CLUSTERS),
        ("vm_start", u64),
        ("vm_end", u64),
        ("vm_kernel_min_size", u64),
        ("max_commands_per_submission", u32),
        ("max_attachments", u32),
        ("command_timestamp_frequency_hz", u64),
    ]


class drm_asahi_get_params(UAPIStructure):
    _fields_ = [("param_group", u32), ("pad", u32),
                ("pointer", u64), ("size", u64)]


class drm_asahi_vm_create(UAPIStructure):
    _fields_ = [("kernel_start", u64), ("kernel_end", u64),
                ("vm_id", u32), ("pad", u32)]


class drm_asahi_vm_destroy(UAPIStructure):
    _fields_ = [("vm_id", u32), ("pad", u32)]


class drm_asahi_gem_create(UAPIStructure):
    _fields_ = [("size", u64), ("flags", u32), ("vm_id", u32),
                ("handle", u32), ("pad", u32)]


class drm_asahi_gem_mmap_offset(UAPIStructure):
    _fields_ = [("handle", u32), ("flags", u32), ("offset", u64)]


class drm_asahi_gem_bind_op(UAPIStructure):
    _fields_ = [("flags", u32), ("handle", u32), ("offset", u64),
                ("range", u64), ("addr", u64)]


class drm_asahi_vm_bind(UAPIStructure):
    _fields_ = [("vm_id", u32), ("num_binds", u32), ("stride", u32),
                ("pad", u32), ("userptr", u64)]


class drm_asahi_gem_bind_object(UAPIStructure):
    _fields_ = [("op", u32), ("flags", u32), ("handle", u32),
                ("vm_id", u32), ("offset", u64), ("range", u64),
                ("object_handle", u32), ("pad", u32)]


class drm_asahi_queue_create(UAPIStructure):
    _fields_ = [("flags", u32), ("vm_id", u32), ("priority", u32),
                ("queue_id", u32), ("usc_exec_base", u64)]


class drm_asahi_queue_destroy(UAPIStructure):
    _fields_ = [("queue_id", u32), ("pad", u32)]


class drm_asahi_sync(UAPIStructure):
    _fields_ = [("sync_type", u32), ("handle", u32),
                ("timeline_value", u64)]


class drm_asahi_cmd_header(UAPIStructure):
    _fields_ = [("cmd_type", u16), ("size", u16),
                ("vdm_barrier", u16), ("cdm_barrier", u16)]


class drm_asahi_submit(UAPIStructure):
    _fields_ = [("syncs", u64), ("cmdbuf", u64), ("flags", u32),
                ("queue_id", u32), ("in_sync_count", u32),
                ("out_sync_count", u32), ("cmdbuf_size", u32),
                ("pad", u32)]


class drm_asahi_attachment(UAPIStructure):
    _fields_ = [("pointer", u64), ("size", u64),
                ("pad", u32), ("flags", u32)]


class drm_asahi_zls_buffer(UAPIStructure):
    _fields_ = [("base", u64), ("comp_base", u64),
                ("stride", u32), ("comp_stride", u32)]


class drm_asahi_timestamp(UAPIStructure):
    _fields_ = [("handle", u32), ("offset", u32)]


class drm_asahi_timestamps(UAPIStructure):
    _fields_ = [("start", drm_asahi_timestamp),
                ("end", drm_asahi_timestamp)]


class drm_asahi_helper_program(UAPIStructure):
    _fields_ = [("binary", u32), ("cfg", u32), ("data", u64)]


class drm_asahi_bg_eot(UAPIStructure):
    _fields_ = [("usc", u32), ("rsrc_spec", u32)]


class drm_asahi_cmd_render(UAPIStructure):
    _fields_ = [
        ("flags", u32), ("isp_zls_pixels", u32),
        ("vdm_ctrl_stream_base", u64),
        ("vertex_helper", drm_asahi_helper_program),
        ("fragment_helper", drm_asahi_helper_program),
        ("isp_scissor_base", u64), ("isp_dbias_base", u64),
        ("isp_oclqry_base", u64),
        ("depth", drm_asahi_zls_buffer),
        ("stencil", drm_asahi_zls_buffer),
        ("zls_ctrl", u64), ("ppp_multisamplectl", u64),
        ("sampler_heap", u64), ("ppp_ctrl", u32),
        ("width_px", u16), ("height_px", u16), ("layers", u16),
        ("sampler_count", u16), ("utile_width_px", u8),
        ("utile_height_px", u8), ("samples", u8), ("sample_size_B", u8),
        ("isp_merge_upper_x", u32), ("isp_merge_upper_y", u32),
        ("bg", drm_asahi_bg_eot), ("eot", drm_asahi_bg_eot),
        ("partial_bg", drm_asahi_bg_eot),
        ("partial_eot", drm_asahi_bg_eot),
        ("isp_bgobjdepth", u32), ("isp_bgobjvals", u32),
        ("ts_vtx", drm_asahi_timestamps),
        ("ts_frag", drm_asahi_timestamps),
    ]


class drm_asahi_cmd_compute(UAPIStructure):
    _fields_ = [
        ("flags", u32), ("sampler_count", u32),
        ("cdm_ctrl_stream_base", u64), ("cdm_ctrl_stream_end", u64),
        ("sampler_heap", u64), ("helper", drm_asahi_helper_program),
        ("ts", drm_asahi_timestamps),
    ]


class drm_asahi_get_time(UAPIStructure):
    _fields_ = [("flags", u64), ("gpu_timestamp", u64)]


@dataclass(frozen=True)
class ParsedCommand:
    index: int
    header: drm_asahi_cmd_header
    payload: object
    vertex_attachments: tuple
    fragment_attachments: tuple
    compute_attachments: tuple
    timestamp_objects: tuple = ()
    hardware_state: object = None


def _parse_attachments(payload):
    size = ctypes.sizeof(drm_asahi_attachment)
    if len(payload) % size:
        raise ValueError("attachment payload is not a whole number of records")
    count = len(payload) // size
    if count > DRM_ASAHI_MAX_ATTACHMENTS:
        raise ValueError("too many Asahi attachments: %d" % count)
    result = []
    for offset in range(0, len(payload), size):
        attachment = drm_asahi_attachment.from_bytes(payload[offset:offset + size])
        if attachment.pad or attachment.flags:
            raise ValueError("attachment padding and flags must be zero")
        result.append(attachment)
    return tuple(result)


def parse_command_buffer(data):
    """Parse and validate one flat modern Asahi command buffer.

    Barrier indices address the prior render/compute events in this submit;
    index zero names all work on that subqueue from previous submits.
    """
    data = bytes(data)
    header_size = ctypes.sizeof(drm_asahi_cmd_header)
    offset = 0
    index = 0
    render_count = 0
    compute_count = 0
    hardware_count = 0
    attachments = {2: (), 3: (), 4: ()}
    commands = []

    while offset < len(data):
        if len(data) - offset < header_size:
            raise ValueError("truncated Asahi command header at %#x" % offset)
        header = drm_asahi_cmd_header.from_bytes(
            data[offset:offset + header_size])
        offset += header_size
        end = offset + header.size
        if end > len(data):
            raise ValueError("truncated Asahi command payload at %#x" % offset)
        raw = data[offset:end]
        offset = end
        index += 1

        if header.cmd_type in (DRM_ASAHI_CMD_RENDER, DRM_ASAHI_CMD_COMPUTE):
            if (header.vdm_barrier != DRM_ASAHI_BARRIER_NONE and
                    header.vdm_barrier > render_count):
                raise ValueError("render barrier refers to future command")
            if (header.cdm_barrier != DRM_ASAHI_BARRIER_NONE and
                    header.cdm_barrier > compute_count):
                raise ValueError("compute barrier refers to future command")
            if header.cmd_type == DRM_ASAHI_CMD_RENDER:
                payload = drm_asahi_cmd_render.from_bytes(raw, extensible=True)
                render_count += 1
            else:
                payload = drm_asahi_cmd_compute.from_bytes(raw, extensible=True)
                if payload.flags:
                    raise ValueError("compute flags must be zero")
                compute_count += 1
            hardware_count += 1
            commands.append(ParsedCommand(
                index, header, payload,
                attachments[DRM_ASAHI_SET_VERTEX_ATTACHMENTS],
                attachments[DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS],
                attachments[DRM_ASAHI_SET_COMPUTE_ATTACHMENTS]))
            continue

        if header.cmd_type not in attachments:
            raise ValueError("unknown Asahi command type %d" % header.cmd_type)
        if (header.vdm_barrier != DRM_ASAHI_BARRIER_NONE or
                header.cdm_barrier != DRM_ASAHI_BARRIER_NONE):
            raise ValueError("attachment commands cannot carry barriers")
        attachments[header.cmd_type] = _parse_attachments(raw)

    if not hardware_count:
        raise ValueError("an Asahi submit needs at least one hardware command")
    if hardware_count > DRM_ASAHI_MAX_COMMANDS:
        raise ValueError("too many Asahi hardware commands: %d" % hardware_count)
    return tuple(commands)


EXPECTED_STRUCTURE_SIZES = {
    drm_asahi_params_global: 592,
    drm_asahi_get_params: 24,
    drm_asahi_vm_create: 24,
    drm_asahi_vm_destroy: 8,
    drm_asahi_gem_create: 24,
    drm_asahi_gem_mmap_offset: 16,
    drm_asahi_gem_bind_op: 32,
    drm_asahi_vm_bind: 24,
    drm_asahi_gem_bind_object: 40,
    drm_asahi_queue_create: 24,
    drm_asahi_queue_destroy: 8,
    drm_asahi_sync: 16,
    drm_asahi_cmd_header: 8,
    drm_asahi_submit: 40,
    drm_asahi_attachment: 24,
    drm_asahi_zls_buffer: 24,
    drm_asahi_timestamp: 8,
    drm_asahi_timestamps: 16,
    drm_asahi_helper_program: 16,
    drm_asahi_bg_eot: 8,
    drm_asahi_cmd_render: 240,
    drm_asahi_cmd_compute: 64,
    drm_asahi_get_time: 16,
}

for _structure, _expected in EXPECTED_STRUCTURE_SIZES.items():
    if ctypes.sizeof(_structure) != _expected:
        raise RuntimeError(
            "%s has host size %d, expected canonical Asahi UAPI size %d" %
            (_structure.__name__, ctypes.sizeof(_structure), _expected))
