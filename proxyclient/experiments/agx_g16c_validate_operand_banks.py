#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit operand-bank DATA in the output-qualified G16C late-client capture.

Read complete descriptors directly from the held UAT snapshots. Correlate
register 0x14028, support+8 and the selected 32-byte dispatch-table directory.
This establishes captured relationships, not who assigns a bank or whether
changing it is safe. No executable page or Apple instruction is inspected.
"""

import argparse
from bisect import bisect_right
import gzip
import hashlib
import json
from pathlib import Path
import struct


DISPATCH = 0xfffffc2001550000


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Capture:
    def __init__(self, directory):
        self.directory = directory
        self.manifest = json.loads((directory / 'manifest.json').read_text())
        assert self.manifest['complete']
        assert not self.manifest['contexts_changed_during_capture']
        assert not self.manifest['table_addresses_changed_during_capture']
        self.mappings = sorted(
            (r for r in self.manifest['mappings']
             if r['context'] == -1 and r['dram']), key=lambda r: r['va'])
        self.virtual_starts = [r['va'] for r in self.mappings]
        self.chunks = sorted(self.manifest['chunks'], key=lambda r: r['pa'])
        self.physical_starts = [r['pa'] for r in self.chunks]
        self.cache = {}

    def read(self, address, length):
        result = bytearray()
        while length:
            at = bisect_right(self.virtual_starts, address) - 1
            assert at >= 0
            mapping = self.mappings[at]
            assert address < mapping['va'] + mapping['size']
            physical = mapping['pa'] + address - mapping['va']
            chunk_index = bisect_right(self.physical_starts, physical) - 1
            assert chunk_index >= 0
            chunk = self.chunks[chunk_index]
            assert physical < chunk['pa'] + chunk['size']
            if chunk_index not in self.cache:
                data = gzip.decompress((self.directory / chunk['file']).read_bytes())
                assert len(data) == chunk['size']
                assert digest(data) == chunk['sha256']
                self.cache[chunk_index] = data
            count = min(length, mapping['va'] + mapping['size'] - address,
                        chunk['pa'] + chunk['size'] - physical)
            offset = physical - chunk['pa']
            result.extend(self.cache[chunk_index][offset:offset + count])
            address += count
            length -= count
        return bytes(result)


def inspect_descriptor(capture, address):
    data = capture.read(address, 0x1000)
    count = struct.unpack_from('<H', data, 0x1e)[0]
    assert 0 < count <= (0x740 - 0x40) // 12
    registers = [struct.unpack_from('<IQ', data, 0x40 + index * 12)
                 for index in range(count)]
    gates = [value for register, value in registers if register == 0x14028]
    assert len(gates) == 1
    bank = gates[0]
    # This reference exercises banks zero and one; do not infer capacity.
    assert bank in (0, 1)
    support_address = struct.unpack_from('<Q', data, 0xfb2)[0]
    support = capture.read(support_address, 0x64)
    support_bank = struct.unpack_from('<I', support, 8)[0]
    directory = struct.unpack_from('<Q', support, 0x14)[0]
    dispatch = capture.read(DISPATCH + bank * 32, 32)
    encoded_directory, read, write, pages = struct.unpack_from('<Q3I', dispatch)
    assert support_bank == bank, (hex(address), bank, support_bank)
    assert encoded_directory == 0x4000000000000000 | directory >> 7
    assert directory % 0x4000 == 0 and pages > 0
    tags = [value for register, value in registers
            if register in (0x10201, 0x10428)]
    assert len(tags) == 2 and tags[0] == tags[1]
    context = struct.unpack_from('<I', data, 0xc)[0]
    assert tags[0] >> 8 == context
    return dict(descriptor=address, descriptor_sha256=digest(data),
                context=context, program_tag=tags[0],
                program_ordinal=tags[0] & 255,
                descriptor_sequence=struct.unpack_from('<Q', data, 4)[0],
                grid=struct.unpack_from('<I', data, 0xf54)[0],
                register_14028=bank, support=support_address,
                support_sha256=digest(support), support_word_08=support_bank,
                directory=directory, dispatch=DISPATCH + bank * 32,
                dispatch_sha256=digest(dispatch),
                read_position=read, write_position=write, pages=pages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True,
                        help='Native late-client artifact with qualified cold replay')
    parser.add_argument('--output', type=Path, required=True,
                        help='New JSON file; never overwrite a prior result')
    args = parser.parse_args()
    root = args.artifact.resolve()
    baseline_path = root / 'cold-replay-v2/result.json'
    baseline = json.loads(baseline_path.read_text())
    assert baseline['pass'] and baseline['all_three_phases_qualified']
    assert not baseline['hypervisor_used'] and not baseline['firmware_failed']
    inventory_path = root / 'captured-backlog-inventory-v1.json'
    inventory = json.loads(inventory_path.read_text())
    phases = {}
    evidence = {str(baseline_path): digest(baseline_path.read_bytes()),
                str(inventory_path): digest(inventory_path.read_bytes())}
    for name in ('warm', 'late', 'resume'):
        directory = root / 'native-held-v2' / name / 'uat'
        capture = Capture(directory)
        plan_path = directory / 'replay-plan.json'
        plan = json.loads(plan_path.read_text())
        assert plan['phase'] == name
        if name == 'late':
            addresses = [record['descriptor'] for group in inventory['rows']
                         for record in group['records'] if record['pending']]
        else:
            addresses = [group['descriptor'] for group in plan['submissions']]
        assert len(addresses) == {'warm': 2, 'late': 9, 'resume': 1}[name]
        phases[name] = [inspect_descriptor(capture, address) for address in addresses]
        for filename in ('manifest.json', 'replay-plan.json'):
            path = directory / filename
            evidence[str(path)] = digest(path.read_bytes())
    warm = phases['warm']
    assert [(r['context'], r['grid'], r['register_14028']) for r in warm] == [
        (1, 0, 0), (1, 1, 0)]
    assert warm[0]['support'] == warm[1]['support']
    parent_late = [r for r in phases['late'] if r['context'] == 1]
    child_late = [r for r in phases['late'] if r['context'] == 2]
    assert len(parent_late) == 8 and len(child_late) == 1
    assert all(r['support'] == warm[0]['support'] and r['register_14028'] == 0
               for r in parent_late)
    assert child_late[0]['register_14028'] == 1
    resumed = phases['resume'][0]
    assert (resumed['context'], resumed['grid'], resumed['register_14028']) == (1, 0, 1)
    assert resumed['support'] != warm[0]['support']
    assert resumed['directory'] != warm[0]['directory']
    # Two different warm queues share the client's tag sequence. The later
    # return changes pools without resetting that sequence. This short capture
    # does not establish wrap behavior or the full tag-allocation protocol.
    parent = [r for phase in phases.values() for r in phase if r['context'] == 1]
    assert [r['program_ordinal'] for r in parent] == list(range(11))
    assert [r['descriptor_sequence'] for r in parent] == [0, 0] + list(range(1, 10))
    assert child_late[0]['program_ordinal'] == 0
    report = dict(pass_=True, scope='Offline DATA audit of previously qualified captures',
                  descriptors_verified=12, phases=phases, evidence_sha256=evidence,
                  register_matches_support_word_08=True,
                  selected_dispatch_directory_matches_support=True,
                  asid_minus_one_is_not_a_general_abi_rule=True,
                  bank_capacity_or_assignment_protocol_proven=False,
                  cause_of_kernel_interleaving_failure_proven=False,
                  parent_program_ordinals=list(range(11)),
                  child_program_ordinal=0,
                  program_tag_wrap_or_allocation_protocol_proven=False,
                  new_hardware_execution=False, apple_binary_disassembly=False)
    report['pass'] = report.pop('pass_')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print('PASS all 12 descriptors: register 0x14028 = support+8; selected DATA '
          'directory matches. Returning ASID1 uses bank1 and a new pool.')


if __name__ == '__main__':
    main()
