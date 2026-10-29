# SPDX-License-Identifier: GPL-2.0-only
"""Firmware-only continuation of the qualified standalone compute queue.

The caller's CDM and shader are opaque. This extracts the source experiment's
ordinary [3,14] continuation and bounded queue recreation. The adapter binds
these descriptor waves to each logical queue's resident transport.
No captured state or test-program builder is imported or called.
"""
import struct

from . import g17g, g17g_backend as backend, g17g_compute as compute, g17g_uat

PAGE_SIZE = 0x4000
PREEMPT_ARENA = 0x7204000000


def transport_state(completed):
    if completed == 0:
        return dict(channel=(0, 0, 0), pointers=(0, 0, 0), queue_limit=0)
    epoch = backend.compute_queue_epoch(completed)
    local = completed - backend.compute_queue_start_ordinal(epoch) + 1
    return dict(channel=(backend.compute_channel_counter(completed),) * 3,
                pointers=(2 * local + 1,) * 3, queue_limit=2 * local + 1)


def compute_wave(commands, completed, addresses, *, priority=2, user_timestamps=None,
                 robustness_base=None, samplers=None):
    commands = tuple((int(base), int(end)) for base, end in commands)
    user_timestamps = ((0, 0),) * len(commands) if user_timestamps is None else tuple(user_timestamps)
    if len(user_timestamps) != len(commands):
        raise ValueError("compute timestamp count differs from command count")
    samplers = ((0, 0),) * len(commands) if samplers is None else tuple(samplers)
    if len(samplers) != len(commands):
        raise ValueError('compute sampler count differs from command count')
    completed = int(completed)
    final = completed + len(commands)
    if not commands or not 0 <= completed < final < (1 << 16):
        raise ValueError("compute wave ordinals must fit positive u16")
    start = completed + 1
    epoch = backend.compute_queue_epoch(start)
    capacity = 20 if epoch else 64
    if len(commands) > capacity or backend.compute_queue_epoch(final) != epoch:
        raise ValueError("compute wave exceeds scheduler or transport capacity")
    if any((base | end) & 3 or not 0 < base < end < (1 << 42) for base, end in commands):
        raise ValueError("invalid opaque CDM bounds")
    g17g.queue_priority_profile(priority)
    if robustness_base is not None and (robustness_base & (PAGE_SIZE - 1) or not 0 < robustness_base < (1 << 42)):
        raise ValueError("invalid compute robustness arena")
    previous = dict(addresses)
    addresses = dict(addresses)
    transport_start = backend.compute_queue_start_ordinal(epoch)
    recreate = bool(epoch and start == transport_start)
    high, low, records, page_flags = [], [], [], {}
    if recreate:
        addresses.update(backend.compute_recreated_queue_addresses(epoch))
        if epoch > backend.COMPUTE_RECREATED_QUEUE_POOL_SIZE:
            retired_epoch = epoch - backend.COMPUTE_RECREATED_QUEUE_POOL_SIZE
            retired_start = backend.compute_queue_start_ordinal(retired_epoch)
            retired_count = backend.compute_queue_command_capacity(retired_epoch)
            # Remove old incoming edges before recycling the bounded slot.
            high.extend((
                (addresses["queue_context"] + 0x200 + (retired_start - 1) * 0x200,
                 bytes(retired_count * 0x200)),
                (addresses["channel_ring"] + compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET +
                 (retired_start - 1) * g17g.RING_SLOT_SIZE,
                 bytes(retired_count * g17g.RING_SLOT_SIZE)),
            ))
        for name, count in (("queue", 1), ("item_ring", 1), ("optional", 1),
                            ("queue_aux", 1), ("scheduler", 2), ("queue_support", 1),
                            ("pointers", 1), ("job_list", 1), ("scheduler_slot", 1)):
            high.append((addresses[name], bytes(count * PAGE_SIZE)))
            flags = (g17g_uat.FLAGS_SHARED_UXN if name in
                     ("pointers", "job_list", "scheduler_slot") else g17g_uat.FLAGS_NORMAL_UXN)
            for offset in range(0, count * PAGE_SIZE, PAGE_SIZE):
                page_flags[addresses[name] + offset] = flags
        for offset, value in ((0, 0x1000000ffff), (0x20, 0x2000000000000), (0x30, 0xff000000)):
            high.append((addresses["queue_aux"] + offset, struct.pack("<Q", value)))
        high.extend((
            (addresses["queue_support"], compute.build_compute_shared_support(
                backend.COMPUTE_CLIENT_STATE, previous["pointers"], active=start)),
            (addresses["optional"], compute.build_compute_optional(
                backend.COMPUTE_QUEUE_CONTEXT_LOW, addresses["queue_context"],
                shared_control=addresses["queue_support"], channel_control=addresses["queue_aux"],
                submission_ordinal=start, token=backend.compute_queue_generation(epoch), first_queue=False)),
            (addresses["queue"], g17g.apply_queue_priority(compute.build_compute_queue_record(
                addresses["pointers"], addresses["item_ring"], addresses["job_list"],
                addresses["queue_aux"], queue_generation=backend.compute_queue_generation(epoch)), priority)),
            (addresses["item_ring"], struct.pack("<Q", addresses["optional"])),
        ))
    if epoch:
        if not recreate:
            high.extend(((addresses["scheduler"], bytes(2 * PAGE_SIZE)),
                         (addresses["job_list"], bytes(PAGE_SIZE)),
                         (addresses["scheduler_slot"], bytes(PAGE_SIZE)),
                         (addresses["queue_support"], struct.pack("<Q", final))))
        high.append((addresses["job_list"] + 8, struct.pack("<Q", addresses["job_list"])))
    for ordinal, (cdm_base, cdm_end) in enumerate(commands, completed + 1):
        index = ordinal - 1
        local_index = ordinal - transport_start
        sub = backend.compute_submission_addresses(ordinal)
        if robustness_base is not None:
            sub['robustness'] = robustness_base + index * 0x40
        # Preserve the proven queue-zero scheduler placement. Its ready word
        # has a separate cyclic index; these are not interchangeable counters.
        ready = ordinal - start + 1 if epoch else backend.compute_scheduler_slot_index(ordinal)
        sub.update(scheduler=addresses["scheduler"] + (ready if epoch else index) * 0x100,
                   dispatch_identity=backend.compute_dispatch_identity(ordinal, epoch),
                   status_a=addresses["status_a"] + index * 0x10,
                   status_b=addresses["status_b"] + index * 0x10,
                   zero_page=addresses["zero_page"] + index * 0x40,
                   event=addresses["event"] + index * compute.COMPUTE_EVENT_SIZE)
        preempt = PREEMPT_ARENA + (index % 64) * 3 * PAGE_SIZE
        low.append((preempt, bytes(3 * PAGE_SIZE)))
        low.append((sub["robustness"], bytes(0x40)))
        registers = compute.build_compute_registers(
            resource=preempt, cdm=cdm_base, robustness=sub["robustness"],
            scratch=backend.COMPUTE_SCRATCH,
            dispatch_identity=sub["dispatch_identity"], work_ordinal=local_index)
        descriptor = compute.build_compute_descriptor(
            registers, sub["scheduler"], sub["descriptor_low"], cdm_end - 4,
            sub["dispatch_identity"], addresses["dispatch_a"], addresses["dispatch_b"],
            # The source executor uses queue-local support on recreation and
            # the global support object on subsequent ordinary waves.
            sub["status_a"], sub["status_b"], addresses["queue_support" if recreate else "shared_support"],
            sub["zero_page"], submit_sequence=local_index, lifecycle_ordinal=ordinal,
            # Standalone's sustained August path left +f58 zero. The later
            # mixed-work default must not silently change this queue profile.
            queue_submission=local_index + 1, queue_ordinal=0,
            user_timestamp_start=user_timestamps[ordinal - completed - 1][0],
            user_timestamp_end=user_timestamps[ordinal - completed - 1][1],
            sampler_heap=samplers[ordinal - completed - 1][0],
            sampler_count=samplers[ordinal - completed - 1][1])[:compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE]
        high.append((sub["descriptor"], descriptor))
        low.append((sub["descriptor_low"], descriptor))
        high.extend((
            (sub["scheduler"], compute.build_compute_scheduler_record(
                addresses["scheduler_slot"], slot_index=ready, work_id=index)),
            (addresses["scheduler_slot"] + ready * 4, struct.pack("<I", 1)),
            (sub["status_a"], bytes(8)), (sub["status_b"], bytes(8)),
            (sub["zero_page"], bytes(0x40)),
            (sub["event"], compute.build_compute_event(group_number=ordinal, generation=2)),
            (addresses["item_ring"] + (1 + 2 * local_index) * 8,
             struct.pack("<2Q", sub["descriptor"], sub["event"])),
            (addresses["channel_ring"] + compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET +
             backend.compute_channel_slot_index(ordinal) * g17g.RING_SLOT_SIZE,
             compute.build_compute_channel_slot(addresses["queue"]) if ordinal == 1 or recreate and local_index == 0 else
             compute.build_compute_repeat_channel_slot(addresses["queue"], item_limit=2 * (local_index + 1) + 1)),
            (addresses["queue_context"] + compute.compute_queue_context_item_offset(index),
             compute.build_compute_queue_context_item(sub["descriptor"], addresses["queue"], item_index=local_index)),
        ))
        records.append(dict(ordinal=ordinal, cdm_base=cdm_base, cdm_end=cdm_end,
                            sampler_heap=samplers[ordinal - completed - 1][0],
                            sampler_count=samplers[ordinal - completed - 1][1],
                            addresses={**addresses, **{key: sub[key] for key in
                                ("descriptor", "status_a", "status_b", "event", "zero_page")}}))
    # Predecessor retirement is checked before the wave becomes visible.
    high.append(g17g.queue_priority_write(addresses["queue"], priority))
    high.extend(((addresses["shared_state"], struct.pack("<I", final)),
                 (addresses["shared_support"], struct.pack("<Q", final)),
                 (addresses["shared_support"] + 0x40, struct.pack("<Q", final << 32))))
    final_state = transport_state(final)
    release = (
        (addresses["pointers"], g17g.build_pointer_block(field_00=0, field_30=0,
             field_40=final_state["queue_limit"])) if recreate else
        (addresses["pointers"] + g17g.POINTER_FIELD_40, struct.pack("<I", final_state["queue_limit"])),
        (addresses["state"] + compute.COMPUTE_CHANNEL_STATE_OFFSET + 0x20,
         struct.pack("<I", backend.compute_channel_counter(final))),
    )
    from .g17g_barriers import high_record_binding
    jobs = tuple((high_record_binding(high, addresses['queue_context'] +
        compute.compute_queue_context_item_offset(row['ordinal']-1), generation=epoch),)
        for row in records)
    return dict(completed=completed, final=final, high=tuple(high), low=tuple(low),
                dependency_jobs=jobs,
                release=release, records=tuple(records), captured_input=None,
                addresses=addresses, previous_addresses=previous, epoch=epoch,
                recreate=recreate, page_flags=page_flags,
                retirement_before=transport_state(completed), retirement_after=final_state)


def compute_waves(bounds, completed, addresses, *, priority=2, user_timestamps=None, robustness_base=None,
                  samplers=None):
    """Split only at firmware scheduler/queue-lifetime boundaries."""
    bounds, waves = tuple(bounds), []
    user_timestamps = ((0, 0),) * len(bounds) if user_timestamps is None else tuple(user_timestamps)
    if len(user_timestamps) != len(bounds):
        raise ValueError("compute timestamp count differs from command count")
    samplers = ((0, 0),) * len(bounds) if samplers is None else tuple(samplers)
    if len(samplers) != len(bounds):
        raise ValueError('compute sampler count differs from command count')
    while bounds:
        epoch = backend.compute_queue_epoch(completed + 1)
        end = backend.compute_queue_start_ordinal(epoch) + backend.compute_queue_command_capacity(epoch) - 1
        count = min(len(bounds), 20 if epoch else 64, end - completed)
        wave = compute_wave(bounds[:count], completed, addresses, priority=priority,
                            user_timestamps=user_timestamps[:count],robustness_base=robustness_base,
                            samplers=samplers[:count])
        waves.append(wave)
        bounds, completed, addresses = bounds[count:], wave["final"], wave["addresses"]
        user_timestamps = user_timestamps[count:]
        samplers = samplers[count:]
    return tuple(waves)


def write_pages(writes):
    return {dva for address, body in writes
            for dva in range(address & -PAGE_SIZE,
                             (address + len(body) + PAGE_SIZE - 1) & -PAGE_SIZE, PAGE_SIZE)}
