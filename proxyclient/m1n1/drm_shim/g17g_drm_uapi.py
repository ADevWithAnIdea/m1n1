# SPDX-License-Identifier: GPL-2.0-only
"""Generic DRM layouts used by the G17G C bridge (drm.h, no UAPI changes)."""
import ctypes
from .g17g_uapi import UAPIStructure, u32, u64


class drm_version(UAPIStructure):
    # Native LP64 DRM discovery layout, shared by the ARM64 Linux client and
    # the Darwin dispatcher harness. Lengths and pointer values are 64 bits.
    _fields_ = [("version_major", ctypes.c_int32),
                ("version_minor", ctypes.c_int32),
                ("version_patchlevel", ctypes.c_int32),
                ("name_len", u64), ("name", u64),
                ("date_len", u64), ("date", u64),
                ("desc_len", u64), ("desc", u64)]


class drm_gem_close(UAPIStructure):
    _fields_ = [("handle", u32), ("pad", u32)]


class drm_get_cap(UAPIStructure):
    _fields_ = [("capability", u64), ("value", u64)]


class drm_syncobj_create(UAPIStructure):
    _fields_ = [("handle", u32), ("flags", u32)]


class drm_syncobj_destroy(UAPIStructure):
    _fields_ = [("handle", u32), ("pad", u32)]


class drm_syncobj_array(UAPIStructure):
    _fields_ = [("handles", u64), ("count_handles", u32), ("pad", u32)]


class drm_syncobj_timeline_array(UAPIStructure):
    _fields_ = [("handles", u64), ("points", u64),
                ("count_handles", u32), ("flags", u32)]


class drm_syncobj_wait(UAPIStructure):
    _fields_ = [("handles", u64), ("timeout_nsec", ctypes.c_int64),
                ("count_handles", u32), ("flags", u32),
                ("first_signaled", u32), ("pad", u32),
                ("deadline_nsec", u64)]


class drm_syncobj_timeline_wait(UAPIStructure):
    _fields_ = [("handles", u64), ("points", u64),
                ("timeout_nsec", ctypes.c_int64), ("count_handles", u32),
                ("flags", u32), ("first_signaled", u32), ("pad", u32),
                ("deadline_nsec", u64)]


class drm_syncobj_transfer(UAPIStructure):
    _fields_ = [("src_handle", u32), ("dst_handle", u32),
                ("src_point", u64), ("dst_point", u64),
                ("flags", u32), ("pad", u32)]
