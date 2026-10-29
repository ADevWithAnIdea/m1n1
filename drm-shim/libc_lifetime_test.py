#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Observe actual embedded file identities across libc fd replacement.

Requires the Mesa G17G interposer in LD_PRELOAD. No GPU operation is issued.
"""
import ctypes
import errno
import gc
import os
from m1n1.g17g_shim_entry import Shim

libc = ctypes.CDLL(None, use_errno=True)
libc.dup3.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
fds = set()
try:
    first = os.open("/dev/dri/renderD128", os.O_RDWR)
    fds.add(first)
    shim, = [obj for obj in gc.get_objects() if isinstance(obj, Shim)]
    initial, = shim.files
    duplicate = os.dup(first)
    fds.add(duplicate)
    assert set(shim.files) == {initial}
    os.close(first)
    fds.remove(first)
    other = os.open("/dev/dri/renderD128", os.O_RDWR)
    fds.add(other)
    second, = set(shim.files) - {initial}
    assert second > initial
    os.dup2(duplicate, other)
    assert set(shim.files) == {initial}, "dup2 must release the replaced file and retain the source identity"
    os.close(duplicate)
    fds.remove(duplicate)
    replacement = os.open("/dev/dri/renderD128", os.O_RDWR)
    fds.add(replacement)
    third, = set(shim.files) - {initial}
    assert third > second
    assert libc.dup3(other, replacement, os.O_CLOEXEC) == replacement
    assert set(shim.files) == {initial}, "dup3 must release the replaced file"
    assert not os.get_inheritable(replacement)
    ctypes.set_errno(0)
    assert libc.dup3(other, other, 0) == -1 and ctypes.get_errno() == errno.EINVAL
    assert set(shim.files) == {initial}
    os.close(other)
    fds.remove(other)
    unrelated = os.open("/dev/null", os.O_RDWR)
    fds.add(unrelated)
    os.dup2(unrelated, replacement)
    assert not shim.files, "non-DRM dup2 replacement must release the last DRM reference"
    assert shim.driver is None, "fd lifetime operations must not initialize the GPU"
    print("PASS libc dup/fcntl/dup2/dup3 replacement, final release and fresh file identities")
finally:
    for fd in fds:
        os.close(fd)
