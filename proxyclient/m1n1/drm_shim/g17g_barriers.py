# SPDX-License-Identifier: GPL-2.0-only
"""G17G queue-context dependencies: predecessor values followed by self.

Native compute/render fence controls identify this list, its active mask and
its two-bit-per-entry mask. Source vertex-withheld/released controls qualify
the dependency's effect independently of queue retirement.
"""
import struct


def dependency_word(queue, value):
    if not 0 <= queue < 256 or not 0 <= value < (1 << 32):
        raise ValueError('G17G dependency queue/value out of range')
    return (queue << 40) | value


def context_dependencies(record):
    """Return predecessor pairs and the final self pair from an owned record."""
    if len(record) != 0x200:
        raise ValueError('G17G queue-context record must be 0x200 bytes')
    mask = struct.unpack_from('<I', record, 0x20)[0]
    count = mask.bit_length()
    if not 1 <= count <= 3 or mask != (1 << count) - 1:
        raise ValueError('unqualified G17G dependency mask')
    if struct.unpack_from('<Q', record, 0x180)[0] != sum(1 << (2*i) for i in range(count)):
        raise ValueError('G17G dependency state mask differs')
    pairs = []
    for index in range(count):
        word = struct.unpack_from('<Q', record, 0x28 + index*8)[0]
        if word & ~((255 << 40) | 0xffffffff):
            raise ValueError('G17G dependency contains reserved bits')
        pairs.append((word >> 40, word & 0xffffffff))
    return tuple(pairs[:-1]), pairs[-1]


def with_dependencies(record, dependencies, *, replace=False):
    """Preserve self ordering and coalesce predecessor waits by hardware queue."""
    prior, own = context_dependencies(record)
    waits = {}
    for queue, value in (() if replace else prior) + tuple(dependencies):
        dependency_word(queue, value)
        if queue == own[0]:
            if value > own[1]:
                raise ValueError('G17G job cannot wait for its own future completion')
            continue  # The final self entry already imposes this queue order.
        waits[queue] = max(value, waits.get(queue, 0))
    if len(waits) > 2:
        raise ValueError('G17G UAPI job exceeds two predecessor queues')
    entries = (*sorted(waits.items()), own)
    out = bytearray(record)
    struct.pack_into('<I', out, 0x20, (1 << len(entries))-1)
    out[0x28:0x40] = bytes(0x18)
    for index, pair in enumerate(entries):
        struct.pack_into('<Q', out, 0x28+index*8, dependency_word(*pair))
    struct.pack_into('<Q', out, 0x180, sum(1 << (2*i) for i in range(len(entries))))
    return bytes(out)


def record_binding(field, key, offset=0, *, generation=0):
    """Location of an owned context record in a not-yet-published graph."""
    return dict(field=field, key=key, offset=offset, generation=generation)


def high_record_binding(writes, address, *, generation=0):
    matches = [index for index, (target, body) in enumerate(writes)
               if target == address and len(body) == 0x200]
    if len(matches) != 1:
        raise ValueError('expected one owned dependency record write')
    return record_binding('high', matches[0], generation=generation)


def bound_record(graph, binding, replacement=None):
    field, key, offset = (binding[name] for name in ('field', 'key', 'offset'))
    container = graph[field]
    body = container[key][1] if field == 'high' else container[key]
    record = body[offset:offset+0x200]
    if len(record) != 0x200:
        raise ValueError('dependency binding escapes its owned context record')
    if replacement is not None:
        body = body[:offset] + replacement + body[offset+0x200:]
        if field == 'high':
            rows = list(container)
            rows[key] = (rows[key][0], body)
            graph[field] = tuple(rows)
        else:
            graph[field] = dict(container)
            graph[field][key] = body
    return record


def apply_submission_barriers(commands, graph, waves):
    """Resolve this ioctl's event indices to firmware predecessor queue/values.

    Index zero is already complete at entry to this synchronous adapter. Queue
    recreation also waits for retirement; dependencies on an earlier lifetime
    need no new firmware wait. Async admission must retain those lifetime/fence
    references instead of relying on these synchronous boundaries.
    """
    from .g17g_uapi import DRM_ASAHI_BARRIER_NONE, DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_CMD_RENDER
    if not any(value not in (0, DRM_ASAHI_BARRIER_NONE)
               for command in commands for value in (command.header.vdm_barrier, command.header.cdm_barrier)):
        return
    jobs, seen = [], set()

    def collect(part):
        if id(part) in seen:
            return
        seen.add(id(part))
        if part.get('format') == 'm1n1-g17g-render-wave-v1':
            for record in part['records']:
                collect(record)
        else:
            jobs.extend((part, bindings) for bindings in part.get('dependency_jobs', ()))

    for part in (graph, *waves):
        collect(part)
    if len(jobs) != len(commands):
        raise ValueError('submission dependency jobs differ from UAPI commands')
    events = {DRM_ASAHI_CMD_RENDER: [None], DRM_ASAHI_CMD_COMPUTE: [None]}
    generations = {}
    for command, (part, bindings) in zip(commands, jobs):
        points = []
        for binding in bindings:
            _, own = context_dependencies(bound_record(part, binding))
            generations[own[0]] = binding['generation']
            points.append((own[0], own[1]+1, binding['generation']))
        if len(bindings) != (2 if command.header.cmd_type == DRM_ASAHI_CMD_RENDER else 1):
            raise ValueError('UAPI command and firmware engine count differ')
        waits = []
        for kind, index in ((DRM_ASAHI_CMD_RENDER, command.header.vdm_barrier),
                            (DRM_ASAHI_CMD_COMPUTE, command.header.cdm_barrier)):
            if index in (0, DRM_ASAHI_BARRIER_NONE):
                continue
            queue, value, generation = events[kind][index]
            if generations[queue] == generation:
                waits.append((queue, value))
        original = bound_record(part, bindings[0])
        bound_record(part, bindings[0], with_dependencies(original, waits))
        part.setdefault('gpu_barriers', []).append(dict(command_index=command.index, waits=waits))
        events[command.header.cmd_type].append(points[-1])
