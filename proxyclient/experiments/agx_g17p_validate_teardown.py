#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline checks for G17P BO teardown and DVA reuse primitives."""

import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.agx.g17p_shim import G17PShimAllocator  # noqa: E402
from m1n1.hw.uat import PTE, Page_PTE, TTBR, UAT  # noqa: E402


PAGE = 0x4000


class FakeSpace:
    def __init__(self):
        self.objects = []
        self.next_pa = 0x80000000
        self.unmapped = []

    def alloc_at(self, va, size, name, **flags):
        map_size = (size + PAGE - 1) & ~(PAGE - 1)
        pa = self.next_pa
        self.next_pa += map_size
        record = {
            "name": name,
            "va": va,
            "pa": pa,
            "size": size,
            "map_va": va,
            "map_pa": pa,
            "map_size": map_size,
            "flags": flags,
        }
        self.objects.append(record)
        return va, pa

    def unmap(self, mapping):
        if mapping not in self.objects:
            return False
        self.objects.remove(mapping)
        self.unmapped.append(mapping)
        return True

    def write(self, _pa, _data):
        pass


def valid_entry(cls, offset):
    entry = cls(VALID=1)
    if cls is not TTBR:
        entry.TYPE = 1
    entry.set_offset(offset)
    return entry


def validate_leaf_unmap():
    uat = object.__new__(UAT)
    uat.gpu_region = 0x100000
    uat.dirty_ranges = {}
    uat._root_walk_cache = {"stale": True}
    uat.init = lambda: None

    l1 = 0x200000
    l2 = 0x204000
    l3 = 0x208000
    leaves = {0: valid_entry(Page_PTE, 0x90000000),
              1: valid_entry(Page_PTE, 0x90004000)}
    writes = []

    def fetch(table, index, _size, cls):
        if cls is TTBR:
            return valid_entry(TTBR, l1)
        if table == l1:
            return valid_entry(PTE, l2)
        if table == l2:
            return valid_entry(PTE, l3)
        if table == l3:
            return leaves.get(index, Page_PTE())
        raise AssertionError("unexpected page-table walk at %#x" % table)

    def write(table, index, _size, pte):
        if table != l3 or not isinstance(pte, Page_PTE):
            raise AssertionError("unmap wrote a non-leaf entry")
        leaves[index] = pte
        writes.append((table, index, int(pte)))

    uat.fetch_pte = fetch
    uat.write_pte = write

    if uat.iounmap(3, 0, 2 * PAGE) != 2 * PAGE:
        raise AssertionError("two mapped leaves were not removed")
    if writes != [(l3, 0, 0), (l3, 1, 0)]:
        raise AssertionError("unexpected invalid leaf writes: %r" % (writes,))
    if uat.dirty_ranges != {3: [(0, 2 * PAGE)]}:
        raise AssertionError("unmap did not record its ASID invalidation range")
    if uat._root_walk_cache:
        raise AssertionError("unmap retained stale root-walk translations")
    if uat.iounmap(3, 0, 2 * PAGE) != 0:
        raise AssertionError("repeated unmap was not idempotent")


def validate_direct_root_unmap():
    uat = object.__new__(UAT)
    uat.dirty_ranges = {}
    uat._root_walk_cache = {"stale": True}

    root = 0x300000
    l2 = 0x304000
    l3 = 0x308000
    leaves = {0: valid_entry(Page_PTE, 0xa0000000),
              1: valid_entry(Page_PTE, 0xa0004000)}
    writes = []

    def fetch(table, index, _size, cls):
        if table == root and cls is PTE:
            return valid_entry(PTE, l2)
        if table == l2 and cls is PTE:
            return valid_entry(PTE, l3)
        if table == l3 and cls is Page_PTE:
            return leaves.get(index, Page_PTE())
        raise AssertionError(
            "unexpected direct-root walk at %#x with %s" %
            (table, cls.__name__))

    def write(table, index, _size, pte):
        if table != l3 or not isinstance(pte, Page_PTE):
            raise AssertionError("direct-root unmap wrote a non-leaf entry")
        leaves[index] = pte
        writes.append((table, index, int(pte)))

    uat.fetch_pte = fetch
    uat.write_pte = write

    if uat.iounmap_root(root, 0, 2 * PAGE, ctx=5) != 2 * PAGE:
        raise AssertionError("direct-root unmap did not remove both leaves")
    if writes != [(l3, 0, 0), (l3, 1, 0)]:
        raise AssertionError("unexpected direct-root leaf writes: %r" % (writes,))
    if uat.dirty_ranges != {5: [(0, 2 * PAGE)]}:
        raise AssertionError("direct-root unmap did not record ASID invalidation")
    if uat._root_walk_cache:
        raise AssertionError("direct-root unmap retained stale translations")


def validate_object_reuse():
    space = FakeSpace()
    allocator = G17PShimAllocator(space, "test", 0x1000000000)
    first = allocator.new(0x2000, name="first")
    first_addr = first._addr
    first_pa = first._pa
    first.free()
    first.free()

    if space.objects or len(space.unmapped) != 1:
        raise AssertionError("object destruction did not release one mapping")
    try:
        first.push(b"x")
    except RuntimeError:
        pass
    else:
        raise AssertionError("a destroyed object remained writable")

    second = allocator.new(0x2000, name="second")
    if second._addr != first_addr:
        raise AssertionError("released DVA was not recycled")
    if second._pa == first_pa:
        raise AssertionError("DVA reuse retained stale physical backing")
    if second._destroyed:
        raise AssertionError("replacement object started destroyed")


def validate_allocator_exhaustion():
    base = 0x1000000000
    space = FakeSpace()
    allocator = G17PShimAllocator(space, "bounded", base, base + PAGE)
    first = allocator.new(PAGE, name="first")
    cursor = allocator.next_va
    objects = list(allocator.objects)
    mappings = list(space.objects)

    try:
        allocator.new(PAGE, name="overflow")
    except MemoryError:
        pass
    else:
        raise AssertionError("allocator accepted an allocation beyond its DVA limit")
    if allocator.next_va != cursor:
        raise AssertionError("failed allocation advanced the DVA cursor")
    if allocator.objects != objects or space.objects != mappings:
        raise AssertionError("failed allocation changed object or mapping ownership")

    first.free()
    replacement = allocator.new(PAGE, name="replacement")
    if replacement._addr != base:
        raise AssertionError("bounded allocator did not reuse released space")


def main():
    validate_leaf_unmap()
    validate_direct_root_unmap()
    validate_object_reuse()
    validate_allocator_exhaustion()
    print("PASS: G17P teardown invalidates context and direct-root leaves and "
          "handles bounded allocation failure without state mutation")


if __name__ == "__main__":
    main()
