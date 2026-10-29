# SPDX-License-Identifier: GPL-2.0-only
"""Owned mixed-history allocation after the common firmware initialization."""
import struct

from . import g17g_defaults as defaults, g17g_initdata as init, g17g_uat as uat

PAGE = 0x4000
HISTORY_RELOCATION = 4 * PAGE
RETAINED_HISTORY_PAGES = 2


def prepare_mixed_history(runtime):
    """Keep initialization aliases alive while selecting mixed history backing.

    The original addresses remain reachable after initdata ACK. Changing only
    the three hardware-data pointers and low aliases allows compute to finish
    but faults on first render. Both old and new heads must share backing.
    This transition is only qualified before the initial control notification.
    """
    if runtime.channel_state() != (0, 0, 1):
        raise RuntimeError("mixed history requires the unused control channel")
    rows = tuple(dict(row) for row in runtime.boot.fields['hwdata_fields']['region_records'])
    if len(rows) != init.HWDATA_REGION_RECORD_COUNT:
        raise ValueError("mixed history record count changed")
    patches, aliases, old_aliases, targets = [], [], [], set()
    for index, record in enumerate(rows[:3]):
        old = record['address_0c']
        if old != defaults.CANONICAL_REGION_ADDRESSES[index]:
            raise RuntimeError("mixed history requires canonical initialization")
        new = old + HISTORY_RELOCATION
        field = init.HWDATA_ADDRESS + init.HWDATA_REGION_RECORDS + index * init.HWDATA_REGION_RECORD_SIZE + 0xc
        patches.append((field, old, new))
        for offset in range(0, uat.CONTEXT0_REGION_ALIAS_PAGE_COUNT * PAGE, PAGE):
            aliases.append((uat.CONTEXT0_ALIAS_BASE + record['word_04'] + offset, new + offset))
            targets.add(new + offset)
        old_aliases.extend((old + offset, new + offset)
                           for offset in range(0, RETAINED_HISTORY_PAGES * PAGE, PAGE))
        record['address_0c'] = new
    pointers = runtime.read_fields({field: (field, 8) for field, old, new in patches})
    if any(pointers[field] != struct.pack('<Q', old) for field, old, new in patches):
        raise RuntimeError("live initialization history pointer changed")

    # Validate every existing owner and preimage before the first mutation.
    missing, present = [], []
    for address in sorted(targets | {old for old, new in old_aliases}):
        mapped = runtime.uat.iotranslate_root(runtime.root, address, PAGE)
        if mapped == [(None, PAGE)] and address in targets and address not in runtime.pages:
            missing.append(address)
        elif mapped == [(runtime.pages.get(address), PAGE)] and address in runtime.pages:
            present.append(address)
        else:
            raise RuntimeError("mixed history mapping has no owned backing at %#x" % address)
    images = runtime.read_fields({address: (address, PAGE) for address in present})
    if any(any(body) for body in images.values()):
        raise RuntimeError("mixed history allocation is not initially empty")

    runtime.evidence['command_publication_started'] = True
    for address in missing:
        runtime.pages[address] = runtime.alloc(PAGE)
        runtime.uat.iomap_at_root(runtime.root, address, runtime.pages[address], PAGE,
                                  **uat.FLAGS_NORMAL_UXN)
    # Snapshot the destinations before replacing overlapping old tail leaves.
    backing = tuple((old, new, runtime.pages[new]) for old, new in old_aliases)
    for old, new, pa in backing:
        runtime.uat.iomap_at_root(runtime.root, old, pa, PAGE, **uat.FLAGS_NORMAL_UXN)
        runtime.pages[old] = pa
    for low, high in aliases:
        runtime.uat.iomap_at_root(runtime.boot.context0_low_root, low, runtime.pages[high], PAGE,
                                  **uat.FLAGS_CONTEXT0_UXN)
    runtime.publish(runtime.pages[address] for address in missing)
    runtime.flush_tables(0)
    runtime.flush_tables(0x40)
    runtime.publish_writes((field, struct.pack('<Q', new)) for field, old, new in patches)
    runtime.boot.fields['hwdata_fields']['region_records'] = rows
    runtime.evidence['history_admission'] = dict(
        created=tuple(missing), low_aliases=tuple(aliases), retained_aliases=old_aliases,
        pointers=tuple((field, old, new) for field, old, new in patches))
