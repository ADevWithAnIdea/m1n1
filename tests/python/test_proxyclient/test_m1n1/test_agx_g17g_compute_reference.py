# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free byte comparison against the qualified source executor.

Load only its one function AST, never the experiment module (which owns setup
and CLI side effects). Stop at its first publication and inspect the objects.
This is test-only reference code, not a driver dependency or captured input.
"""
import ast
from functools import lru_cache
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from m1n1.drm_shim import g17g, g17g_backend as backend, g17g_compute as compute, g17g_uat
from m1n1.drm_shim.g17g_compute_queue import compute_wave

PAGE = 0x4000


@lru_cache(None)
def reference_code():
    path = Path(__file__).with_name("_g17g_compute_reference.py")
    # AST processing is necessary to avoid importing any hardware setup.
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "publish_compute_batch")
    return compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec")


def reference_publications(count, *, start=2, epoch=0, recreate=False):
    addresses = backend.compute_addresses()
    previous_epoch = backend.compute_queue_epoch(start - 1)
    if previous_epoch:
        addresses.update(backend.compute_recreated_queue_addresses(previous_epoch))
    graph = backend.build_add_compute_graph()
    images = {addresses[name]: bytearray(body) for name, body in graph["firmware_objects"].items()}
    images[addresses["state"]] = bytearray(PAGE)
    counter = backend.compute_channel_counter(start - 1)
    struct.pack_into("<I12xI12xI", images[addresses["state"]], compute.COMPUTE_CHANNEL_STATE_OFFSET,
                     counter, counter, counter)
    limit = 2 * (start - backend.compute_queue_start_ordinal(backend.compute_queue_epoch(start - 1))) + 1
    struct.pack_into("<I", images[addresses["queue"]], 0x1c, limit)
    for offset in (0, 0x30, 0x40):
        struct.pack_into("<I", images[addresses["pointers"]], offset, limit)
    next_pa = 0x30000000000
    reverse = {}

    def allocate(_align, size):
        nonlocal next_pa
        result = next_pa
        next_pa += size + PAGE
        return result

    def map_pages(_root, dva, pa, size, **flags):
        for offset in range(0, size, PAGE):
            reverse[pa + offset] = dva + offset

    class Collected(Exception):
        pass

    physical = []
    def collect(publications):
        physical.extend((pa, bytes(body)) for pa, body in publications)
        raise Collected

    uat = Mock(dirty=[])
    uat.iomap_at_root.side_effect = map_pages
    uat.iotranslate_root.return_value = [(None, PAGE)]
    proxy = Mock()
    proxy.memset32.side_effect = lambda pa, value, size: physical.append((pa, bytes(size)))
    namespace = dict(
        g17g=g17g, g17g_backend=backend, g17g_compute=compute, g17g_uat=g17g_uat,
        PAGE_SIZE=PAGE, struct=struct, u=SimpleNamespace(memalign=allocate), p=proxy,
        compute_page_pa=lambda address, *_args: address,
        read_physical=lambda pa, size: bytes(images[pa & -PAGE][pa % PAGE:pa % PAGE + size]),
        write_physical_publications=collect,
        write_physical_retry=lambda pa, body: physical.append((pa, bytes(body))),
    )
    exec(reference_code(), namespace)
    context = dict(root0_pa=0x10000, ram_pages={dva: dva for dva in graph["context1_dvas"]})
    try:
        namespace["publish_compute_batch"](uat, 0x20000, context, {}, {}, {}, addresses,
                                            (), 0x8300000000000a, count,
                                            start_ordinal=start, queue_epoch=epoch, recreate_transport=recreate)
    except Collected:
        result = []
        for pa, body in physical:
            offset = 0
            while offset < len(body):
                address = pa + offset
                dva = reverse.get(address & -PAGE, address & -PAGE) + address % PAGE
                size = min(len(body) - offset, PAGE - address % PAGE)
                result.append((dva, body[offset:offset + size]))
                offset += size
        return tuple(result)
    raise AssertionError("reference escaped its first-publication stop")


def byte_map(writes):
    return {address + offset: value for address, body in writes for offset, value in enumerate(body)}


def include_retained_priority(reference, queue_address):
    # The UAPI adapter can change logical queue priority between waves. Its
    # explicit default-profile publication must match the source opening's
    # already retained profile byte-for-byte; all other source bytes still
    # have their original strict comparison below.
    original = backend.build_add_compute_graph()['firmware_objects']['queue']
    reference.update(byte_map(((queue_address+0x28,original[0x28:0x40]),)))


class TestComputeReference(unittest.TestCase):
    def test_recreated_transport_firmware_bytes_match_source(self):
        for start, count, recreate in ((128, 147, True), (148, 160, False),
                                      (240, 254, False), (255, 260, True),
                                      (261, 280, False), (763, 764, True)):
            with self.subTest(start=start, end=count):
                self.compare_later_wave(start, count, recreate)

    def compare_later_wave(self, start, count, recreate):
        epoch = backend.compute_queue_epoch(start)
        reference = byte_map((address, body) for address, body in
            reference_publications(count, start=start, epoch=epoch, recreate=recreate)
            if address >= 0xfffffc0000000000)
        clients = tuple(backend.compute_client_submission_addresses(i) for i in range(start, count + 1))
        resource_by_cdm = {client["cdm"]: client["resource"] for client in clients}
        build_registers = compute.build_compute_registers
        def reference_resource(**kwargs):
            kwargs["resource"] = resource_by_cdm[kwargs["cdm"]]
            return build_registers(**kwargs)
        with patch.object(compute, "build_compute_registers", side_effect=reference_resource):
            addresses = backend.compute_addresses()
            previous_epoch = backend.compute_queue_epoch(start - 1)
            if previous_epoch:
                addresses.update(backend.compute_recreated_queue_addresses(previous_epoch))
            wave = compute_wave(tuple((client["cdm"], client["cdm"] + 0x30) for client in clients),
                                start - 1, addresses)
        actual = byte_map(wave["high"])
        include_retained_priority(reference,wave['addresses']['queue'])
        different = sorted(a for a in reference.keys() & actual.keys() if reference[a] != actual[a])
        self.assertFalse(different, [(hex(a), reference[a], actual[a]) for a in different[:16]])
        # Runtime allocations zero newly installed pages. Extra explicitly
        # zeroed padding is equivalent; no nonzero source field may be absent.
        self.assertFalse([(hex(a), v) for a, v in reference.items() if a not in actual and v][:16])
        self.assertFalse([(hex(a), v) for a, v in actual.items() if a not in reference and v][:16])

    def test_first_epoch_firmware_publications_match_qualified_source(self):
        count = 16
        expected = reference_publications(count)
        clients = tuple(backend.compute_client_submission_addresses(i) for i in range(2, count + 1))
        resource_by_cdm = {client["cdm"]: client["resource"] for client in clients}
        build_registers = compute.build_compute_registers
        def use_reference_resource(**kwargs):
            # Only neutralize the intentional private-preemption relocation;
            # the production builder still gets no caller shader/argument data.
            kwargs["resource"] = resource_by_cdm[kwargs["cdm"]]
            return build_registers(**kwargs)
        with patch.object(compute, "build_compute_registers", side_effect=use_reference_resource):
            wave = compute_wave(tuple((client["cdm"], client["cdm"] + 0x30) for client in clients),
                                1, backend.compute_addresses())
        actual = byte_map(wave["high"])
        reference = byte_map((address, body) for address, body in expected if address >= 0xfffffc0000000000)
        include_retained_priority(reference,wave['addresses']['queue'])
        missing = sorted(set(reference) - set(actual))
        extra = sorted(set(actual) - set(reference))
        different = sorted(address for address in actual.keys() & reference.keys()
                           if actual[address] != reference[address])
        self.assertEqual((missing[:8], extra[:8], different[:8]), ([], [], []),
                         "high firmware publication mismatch: %r" % {
                             "missing": [hex(a) for a in missing[:8]], "extra": [hex(a) for a in extra[:8]],
                             "different": [(hex(a), actual[a], reference[a]) for a in different[:8]]})
        reference = byte_map(expected)
        actual = byte_map(wave["low"])
        for ordinal in range(2, count + 1):
            start = backend.compute_submission_addresses(ordinal)["descriptor_low"]
            extent = range(start, start + compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE)
            with self.subTest(low_descriptor=ordinal):
                self.assertEqual(bytes(actual[address] for address in extent),
                                 bytes(reference[address] for address in extent))
