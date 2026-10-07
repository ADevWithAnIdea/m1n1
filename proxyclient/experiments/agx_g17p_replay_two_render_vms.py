#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full native capture replay: two processes, identical DVAs, distinct roots.

Diagnostic only. No captured page enters the source-built shim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from agx_g17p_replay_latest_partial import execute_replay

PAGE, SIZE = 0x4000, 0x10000
CONTEXTS = (1, 2)
BASES = tuple(0x10000058000 + index * 0x18000 for index in range(8))
PAGES = tuple(base + offset for base in BASES for offset in range(0, SIZE, PAGE))


def expected_image(attachment):
    body = bytearray(SIZE)
    for offset in (0x7efc, 0x7f00):
        struct.pack_into('<f', body, offset, float(attachment + 1))
    return bytes(body)


def validate_capture(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['chip_id'] != 0x8140 or manifest['unsupported_entries']:
        raise ValueError('incomplete/non-Neo capture')
    if manifest.get('held_native_producer_stores'):
        raise ValueError('this capture must contain the literal published pair')
    ram = (directory / manifest['ram_file']).read_bytes()
    for data, records, digest in (
            (ram, manifest['blob_pages'], manifest['ram_sha256']),
            ((directory / manifest['tables_file']).read_bytes(),
             manifest['table_page_records'], manifest['tables_sha256'])):
        if len(data) != PAGE * len(records) or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('capture image length/hash mismatch')
        if {row['index'] for row in records} != set(range(len(records))):
            raise ValueError('capture page indices are incomplete')
        for row in records:
            start = row['index'] * PAGE
            if hashlib.sha256(data[start:start + PAGE]).hexdigest() != row['sha256']:
                raise ValueError('capture page hash mismatch')
    for region in manifest['fixed_regions']:
        data = (directory / region['file']).read_bytes()
        if len(data) != region['size'] or hashlib.sha256(data).hexdigest() != region['sha256']:
            raise ValueError('fixed data region length/hash mismatch')
    physical = set()
    for context in CONTEXTS:
        groups = [group for group in manifest['root_mappings']
                  if group['root_ctx_id'] == context and group['selector'] == 0]
        if len(groups) != 1:
            raise ValueError('missing/ambiguous native client root')
        mappings = {row['va']: row for row in groups[0]['mappings']}
        for address in PAGES:
            row = mappings[address]
            if row['pa'] in physical or row['blob_index'] is None:
                raise ValueError('client outputs alias or lack captured backing')
            physical.add(row['pa'])
            start = row['blob_index'] * PAGE
            if any(ram[start:start + PAGE]):
                raise ValueError('native output was not zero before the held kick')
    return dict(ram_pages=len(manifest['blob_pages']), client_output_pages=len(physical))


def validate_outputs(records, read):
    keys = {(context, address) for context in CONTEXTS for address in PAGES}
    by_owner = {(row['context'], row['dva']): row for row in records}
    if len(records) != len(keys) or set(by_owner) != keys:
        raise ValueError('replay did not retain every page for both VM owners')
    if len({row['pa'] for row in records}) != len(records):
        raise ValueError('replay client outputs alias physical backing')
    for context in CONTEXTS:
        for attachment, base in enumerate(BASES):
            pages = [by_owner[context, base + offset] for offset in range(0, SIZE, PAGE)]
            for row in pages:
                if len(read(row['before_file'])) != PAGE or len(read(row['after_file'])) != PAGE:
                    raise ValueError('short replay output page')
            before = b''.join(read(row['before_file']) for row in pages)
            after = b''.join(read(row['after_file']) for row in pages)
            if any(before) or after != expected_image(attachment):
                raise ValueError('incorrect full output for context %d attachment %d' %
                                 (context, attachment))
    return dict(contexts=list(CONTEXTS), complete_outputs=16, independent_pages=64)


def validate_replay(directory):
    records = json.loads((directory / 'render_watch.json').read_text())
    result = validate_outputs(records, lambda name: (directory / name).read_bytes())
    (directory / 'two_render_vms_oracle.json').write_text(json.dumps(result, indent=2) + '\n')
    print('TWO NATIVE RENDER VMS FULL-OUTPUT PASS:', result, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    print('FULL CAPTURE:', validate_capture(args.snapshot), flush=True)
    if not args.check_only:
        execute_replay(label='two_render_vms', snapshot=args.snapshot,
                       extra_args=('--watch-extra-context', '2'),
                       output_dvas=PAGES, validate=validate_replay,
                       wait_for_work_events=2)


if __name__ == '__main__':
    main()
