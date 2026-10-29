# SPDX-License-Identifier: GPL-2.0-only
def publish_compute_batch(uat, root_pa, context1, plan, postcontrol,
                          fresh_firmware_pages, addresses, asces,
                          work_message, count, start_ordinal=2,
                          recreate_transport=False, queue_epoch=0,
                          include_coprocessor_sys=True,
                          reuse_context_buffers=False, graph_profile=None,
                          reuse_queue_group=False,
                          coherent_render_target_dva=None,
                          recreate_after_fault=False,
                          allow_inexact=False):
    """Publish one bounded range of independent commands and drain it once."""
    count = int(count)
    start_ordinal = int(start_ordinal)
    if not 2 <= start_ordinal <= count < (1 << 16):
        raise ValueError("compute batch ordinal range is invalid")
    if count - start_ordinal + 1 > 64:
        raise ValueError("one compute batch wave supports at most 64 commands")
    recreate_transport = bool(recreate_transport)
    recreate_after_fault = bool(recreate_after_fault)
    allow_inexact = bool(allow_inexact)
    queue_epoch = int(queue_epoch)
    graph_profile = {} if graph_profile is None else dict(graph_profile)
    mixed_recreated_transport = bool(
        recreate_transport
        and graph_profile.get("format") in (
            "m1n1-t8142-g17g-host-mixed-compute-graph-v1",
            "m1n1-t8142-g17g-host-mixed-compute-graph-v2",
        )
    )
    if recreate_after_fault and not recreate_transport:
        raise ValueError("post-fault queue creation must recreate transport")
    transport_start_ordinal = (
        start_ordinal
        if mixed_recreated_transport or recreate_after_fault else
        g17g_backend.compute_queue_start_ordinal(queue_epoch)
    )
    if not transport_start_ordinal <= start_ordinal:
        raise ValueError("compute batch precedes its transport epoch")
    if recreate_transport and (
        queue_epoch == 0 or start_ordinal != transport_start_ordinal
    ):
        raise ValueError(
            "compute transport recreation must start a nonzero queue epoch"
        )
    addresses = dict(addresses)
    reuse_queue_group = bool(reuse_queue_group)
    scratch_address = int(graph_profile.get(
        "scratch_address", g17g_backend.COMPUTE_SCRATCH
    ))
    robustness_base = int(graph_profile.get(
        "robustness_address", g17g_backend.COMPUTE_ROBUSTNESS
    ))
    dispatch_identity_base = int(graph_profile.get(
        "dispatch_identity", g17g_backend.COMPUTE_DISPATCH_IDENTITY
    ))
    queue_context_low = g17g_backend.COMPUTE_QUEUE_CONTEXT_LOW
    queue_generation = g17g_backend.compute_queue_generation(queue_epoch)
    previous_pointer_address = int(addresses["pointers"])
    descriptor_control = int(addresses["shared_support"])

    def active_page_pa(address):
        address = int(address)
        page = address & ~(PAGE_SIZE - 1)
        pa = fresh_firmware_pages.get(page)
        if pa is not None:
            return int(pa) + address - page
        return compute_page_pa(address, plan, postcontrol)

    state_pa = active_page_pa(addresses["state"])
    queue_pa = active_page_pa(addresses["queue"])
    pointer_pa = active_page_pa(addresses["pointers"])
    item_ring_pa = active_page_pa(addresses["item_ring"])
    channel_ring_pa = active_page_pa(addresses["channel_ring"])
    shared_state_pa = active_page_pa(addresses["shared_state"])
    shared_support_pa = active_page_pa(addresses["shared_support"])
    scheduler_slot_pa = active_page_pa(addresses["scheduler_slot"])

    def lifecycle_state():
        state_body = read_physical(state_pa, PAGE_SIZE)
        queue_body = read_physical(queue_pa, PAGE_SIZE)
        pointer_body = read_physical(pointer_pa, PAGE_SIZE)
        return {
            "channel": list(struct.unpack_from(
                "<I12xI12xI",
                state_body,
                g17g_compute.COMPUTE_CHANNEL_STATE_OFFSET,
            )),
            "queue": g17g.parse_queue_record(
                queue_body[:g17g.QUEUE_RECORD_SIZE]
            ),
            "pointer": g17g.parse_pointer_block(
                pointer_body[:g17g.POINTER_BLOCK_OBSERVED_SIZE]
            ),
        }

    lifecycle_before = lifecycle_state()
    completed_ordinal = start_ordinal - 1
    completed_channel_counter = g17g_backend.compute_channel_counter(
        completed_ordinal
    )
    if lifecycle_before["channel"] != [
        completed_channel_counter,
        completed_channel_counter,
        completed_channel_counter,
    ]:
        raise RuntimeError(
            "compute batch needs retired first command, got %r"
            % lifecycle_before["channel"]
        )
    completed_item_limit = (
        3
        if mixed_recreated_transport or recreate_after_fault else
        2 * g17g_backend.compute_queue_command_capacity(queue_epoch - 1) + 1
        if recreate_transport else
        3 * completed_ordinal
        if reuse_queue_group else
        2 * (completed_ordinal - transport_start_ordinal + 1) + 1
    )
    if lifecycle_before["queue"]["limit_1c"] != completed_item_limit:
        raise RuntimeError("compute batch queue limit is not retired")
    if reuse_queue_group:
        pointer_before = tuple(
            lifecycle_before["pointer"][name]
            for name in ("field_00", "field_30", "field_40")
        )
        if pointer_before not in ((0, 0, 0), (3, 3, 3)):
            raise RuntimeError(
                "mixed compute batch pointer is not service-idle: %r"
                % (pointer_before,)
            )
    elif (
        mixed_recreated_transport
    ):
        pointer_before = tuple(
            lifecycle_before["pointer"][name]
            for name in ("field_00", "field_30", "field_40")
        )
        if pointer_before not in ((0, 0, 0), (3, 3, 3)):
            raise RuntimeError(
                "mixed predecessor pointer is neither idle nor retired: %r"
                % (pointer_before,)
            )
    elif lifecycle_before["pointer"]["field_40"] != completed_item_limit:
        raise RuntimeError("compute batch pointer limit is not retired")

    # All command-owned A/B/output pages are one physical run. This makes the
    # final proof one cache handoff and one transport read, independent of the
    # number of queued commands.
    command_count = count - start_ordinal + 1
    if reuse_queue_group and command_count != 1:
        raise ValueError(
            "reused compute queue groups require one command per wave"
        )
    reuse_context_buffers = bool(reuse_context_buffers)
    if reuse_context_buffers and command_count != 1:
        raise ValueError(
            "context-local compute buffers require one command per wave"
        )
    buffer_backing_size = (
        0 if reuse_context_buffers else command_count * 3 * PAGE_SIZE
    )
    buffer_backing_pa = (
        None if reuse_context_buffers else
        int(u.memalign(PAGE_SIZE, buffer_backing_size))
    )
    if buffer_backing_pa is not None:
        p.memset32(buffer_backing_pa, 0, buffer_backing_size)
    buffer_pas = {}
    dirty_before = set(map(int, uat.dirty))
    recreated_pages = {}
    recycled_queue_epoch = None

    def buffer_addresses_for_ordinal(ordinal):
        if reuse_context_buffers:
            return {
                "a": g17g_backend.COMPUTE_BUFFER_A,
                "b": g17g_backend.COMPUTE_BUFFER_B,
                "out": g17g_backend.COMPUTE_BUFFER_OUT,
            }
        return g17g_backend.compute_batch_buffer_addresses(ordinal)

    if recreate_transport:
        recreated = g17g_backend.compute_recreated_queue_addresses(
            queue_epoch
        )
        if queue_epoch > g17g_backend.COMPUTE_RECREATED_QUEUE_POOL_SIZE:
            recycled_queue_epoch = (
                queue_epoch
                - g17g_backend.COMPUTE_RECREATED_QUEUE_POOL_SIZE
            )
        for name, flags, page_count in (
            ("queue", g17g_uat.FLAGS_NORMAL_UXN, 1),
            ("item_ring", g17g_uat.FLAGS_NORMAL_UXN, 1),
            ("optional", g17g_uat.FLAGS_NORMAL_UXN, 1),
            ("queue_aux", g17g_uat.FLAGS_NORMAL_UXN, 1),
            ("scheduler", g17g_uat.FLAGS_NORMAL_UXN, 2),
            ("queue_support", g17g_uat.FLAGS_NORMAL_UXN, 1),
            ("pointers", g17g_uat.FLAGS_SHARED_UXN, 1),
            ("job_list", g17g_uat.FLAGS_SHARED_UXN, 1),
            ("scheduler_slot", g17g_uat.FLAGS_SHARED_UXN, 1),
        ):
            dva = int(recreated[name])
            addresses[name] = dva
            for page_index in range(page_count):
                page_dva = dva + page_index * PAGE_SIZE
                translated = uat.iotranslate_root(
                    root_pa, page_dva, PAGE_SIZE
                )
                mapped = [
                    int(pa) for pa, _length in translated if pa is not None
                ]
                prior_pa = fresh_firmware_pages.get(page_dva)
                if mapped:
                    if len(mapped) != 1 or prior_pa != mapped[0]:
                        raise RuntimeError(
                            "compute queue slot has foreign mapping at %#x"
                            % page_dva
                        )
                    pa = int(prior_pa)
                else:
                    if prior_pa is not None:
                        raise RuntimeError(
                            "compute queue slot lost mapping at %#x" % page_dva
                        )
                    pa = int(u.memalign(PAGE_SIZE, PAGE_SIZE))
                    uat.iomap_at_root(
                        root_pa, page_dva, pa, PAGE_SIZE, **flags
                    )
                    fresh_firmware_pages[page_dva] = pa
                p.memset32(pa, 0, PAGE_SIZE)
                recreated_pages[page_dva] = pa
        # The earliest native second queue reuses the original paired context
        # aliases and keeps global work identity.  Its selector-15 and
        # descriptor both point at a new support object.  Native allocator
        # reuse placed that object at the retired queue-zero address, but its
        # contents prove it is support state rather than a predecessor link:
        # active global ordinal, caller state, and the preceding pointer block.
        descriptor_control = int(addresses["queue_support"])
        queue_pa = recreated_pages[addresses["queue"]]
        pointer_pa = recreated_pages[addresses["pointers"]]
        item_ring_pa = recreated_pages[addresses["item_ring"]]
        scheduler_slot_pa = recreated_pages[addresses["scheduler_slot"]]
        job_list_body = bytearray(PAGE_SIZE)
        struct.pack_into(
            "<Q",
            # A fresh queue owns an empty intrusive scheduler head whose
            # second qword points back to the head itself.
            job_list_body,
            0x08,
            addresses["job_list"],
        )
        write_physical_retry(
            recreated_pages[addresses["job_list"]], job_list_body
        )
        queue_aux_body = bytearray(PAGE_SIZE)
        for offset, value in (
            (0x00, 0x1000000FFFF),
            (0x20, 0x2000000000000),
            (0x30, 0xFF000000),
        ):
            struct.pack_into("<Q", queue_aux_body, offset, value)
        write_physical_retry(
            recreated_pages[addresses["queue_aux"]], queue_aux_body
        )

    def submission_for_ordinal(ordinal):
        submission = dict(g17g_backend.compute_submission_addresses(ordinal))
        if reuse_queue_group:
            submission["dispatch_identity"] = (
                dispatch_identity_base
                + (ordinal - 1)
                * g17g_backend.COMPUTE_MIXED_REPEAT_DISPATCH_IDENTITY_STRIDE
            )
        else:
            submission["dispatch_identity"] = (
                dispatch_identity_base
                + (ordinal - 1)
                * g17g_backend.COMPUTE_DISPATCH_IDENTITY_STRIDE
                - queue_epoch * (
                    g17g_backend.COMPUTE_DISPATCH_IDENTITY_STRIDE
                    - g17g_backend.COMPUTE_NEW_QUEUE_DISPATCH_IDENTITY_STRIDE
                )
            )
        if queue_epoch:
            scheduler_slot_index = ordinal - start_ordinal + 1
            if (
                scheduler_slot_index
                > g17g_backend.COMPUTE_RECREATED_SCHEDULER_RECORD_COUNT
            ):
                raise RuntimeError(
                    "compute command exceeds recreated scheduler arena"
                )
            submission["scheduler"] = (
                addresses["scheduler"] + scheduler_slot_index * 0x100
            )
        else:
            index = ordinal - 1
            submission.update({
                "scheduler": addresses["scheduler"] + index * 0x100,
                "scheduler_slot": addresses["scheduler_slot"] + index * 4,
                "status_a": addresses["status_a"] + index * 0x10,
                "status_b": addresses["status_b"] + index * 0x10,
                "zero_page": addresses["zero_page"] + index * 0x40,
                "event": (
                    addresses["event"]
                    + index * g17g_compute.COMPUTE_EVENT_SIZE
                ),
            })
        submission["robustness"] = robustness_base + (ordinal - 1) * 0x40
        if reuse_queue_group:
            index = ordinal - 1
            item_start = 3 * index
            submission.update({
                "optional": (
                    addresses["optional"]
                    + item_start * g17g_compute.COMPUTE_OPTIONAL_SIZE
                ),
                "descriptor": (
                    addresses["descriptor"]
                    + index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
                ),
                "descriptor_low": (
                    g17g_backend.COMPUTE_DESCRIPTOR_LOW
                    + index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
                ),
                "scheduler": addresses["scheduler"] + index * 0x100,
                # The mixed queue's first native command occupies status
                # pair one; its immediately following command uses pair zero.
                "status_a": g17g_backend.COMPUTE_GLOBAL_STATUS_A,
                "status_b": g17g_backend.COMPUTE_GLOBAL_STATUS_B,
                "zero_page": addresses["zero_page"] + index * 0x40,
                "event": (
                    addresses["event"]
                    + item_start * g17g_compute.COMPUTE_EVENT_SIZE
                ),
            })
        return submission
    for command_index, ordinal in enumerate(
        range(start_ordinal, count + 1)
    ):
        buffer_addresses = buffer_addresses_for_ordinal(ordinal)
        for buffer_index, name in enumerate(("a", "b", "out")):
            dva = buffer_addresses[name]
            if reuse_context_buffers:
                pa = context1["ram_pages"].get(dva)
                if pa is None:
                    raise RuntimeError(
                        "context-local compute buffer is absent at %#x" % dva
                    )
            else:
                if dva in context1["ram_pages"]:
                    raise RuntimeError(
                        "fresh batched compute buffer already exists at %#x"
                        % dva
                    )
                pa = (
                    buffer_backing_pa
                    + (command_index * 3 + buffer_index) * PAGE_SIZE
                )
                uat.iomap_at_root(
                    int(context1["root0_pa"]),
                    dva,
                    pa,
                    PAGE_SIZE,
                    ctx=1,
                    **g17g_uat.FLAGS_CONTEXT0_UXN,
                )
                context1["ram_pages"][dva] = pa
            buffer_pas[(ordinal, name)] = pa

    new_client_pages = {}
    client_specs = []
    client_spec_dvas = set()
    for ordinal in range(start_ordinal, count + 1):
        client = (
            {
                "shader": g17g_backend.COMPUTE_MIXED_SHADER,
                "cdm": g17g_backend.COMPUTE_MIXED_CDM,
                "resource": g17g_backend.COMPUTE_MIXED_RESOURCE,
            }
            if reuse_queue_group else
            g17g_backend.compute_client_submission_addresses(ordinal)
        )
        submission = submission_for_ordinal(ordinal)
        for base, page_count, flags in (
            (client["shader"], 2, g17g_uat.FLAGS_CONTEXT0_UXN),
            (
                client["cdm"], 2,
                g17g_uat.FLAGS_CONTEXT0_EXECUTABLE,
            ),
            (client["resource"], 3, g17g_uat.FLAGS_CONTEXT0_UXN),
            (
                submission["robustness"] & ~(PAGE_SIZE - 1),
                1,
                g17g_uat.FLAGS_CONTEXT0_UXN,
            ),
        ):
            for page_index in range(page_count):
                dva = int(base) + page_index * PAGE_SIZE
                if (
                    dva not in context1["ram_pages"]
                    and dva not in client_spec_dvas
                ):
                    client_specs.append((dva, flags))
                    client_spec_dvas.add(dva)
    later_client_page_count = len(client_specs)
    later_client_backing_pa = None
    if later_client_page_count:
        later_client_backing_pa = int(u.memalign(
            PAGE_SIZE, later_client_page_count * PAGE_SIZE
        ))
        p.memset32(
            later_client_backing_pa,
            0,
            later_client_page_count * PAGE_SIZE,
        )
    later_client_index = 0
    for dva, flags in client_specs:
        pa = later_client_backing_pa + later_client_index * PAGE_SIZE
        later_client_index += 1
        uat.iomap_at_root(
            int(context1["root0_pa"]),
            dva,
            pa,
            PAGE_SIZE,
            ctx=1,
            **flags,
        )
        context1["ram_pages"][dva] = pa
        new_client_pages[dva] = pa
    if later_client_index != later_client_page_count:
        raise RuntimeError("batched compute client-page accounting changed")

    def resolve_firmware_page(page):
        page = int(page) & ~(PAGE_SIZE - 1)
        pa = fresh_firmware_pages.get(page)
        if pa is not None:
            return int(pa)
        try:
            return compute_page_pa(page, plan, postcontrol)
        except RuntimeError:
            pa = int(u.memalign(PAGE_SIZE, PAGE_SIZE))
            p.memset32(pa, 0, PAGE_SIZE)
            uat.iomap_at_root(
                root_pa,
                page,
                pa,
                PAGE_SIZE,
                **g17g_uat.FLAGS_NORMAL_UXN,
            )
            fresh_firmware_pages[page] = pa
            return pa

    # Descriptors 4, 8, ... straddle firmware pages. Grow the high arena on
    # demand and always publish both high and low views as physical scatters.
    descriptor_high_pages = {}
    descriptor_low_pages = {}
    new_descriptor_low_pages = {}
    descriptor_size = g17g_compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE
    for ordinal in range(start_ordinal, count + 1):
        submission = submission_for_ordinal(ordinal)
        for address, destination in (
            (submission["descriptor"], descriptor_high_pages),
            (submission["descriptor_low"], descriptor_low_pages),
        ):
            end = address + descriptor_size
            for page in range(
                address & ~(PAGE_SIZE - 1),
                (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),
                PAGE_SIZE,
            ):
                if page in destination:
                    continue
                if destination is descriptor_low_pages:
                    pa = context1["ram_pages"].get(page)
                    if pa is None:
                        pa = int(u.memalign(PAGE_SIZE, PAGE_SIZE))
                        p.memset32(pa, 0, PAGE_SIZE)
                        uat.iomap_at_root(
                            int(context1["root0_pa"]),
                            page,
                            pa,
                            PAGE_SIZE,
                            ctx=1,
                            **g17g_uat.FLAGS_CONTEXT0_UXN,
                        )
                        context1["ram_pages"][page] = pa
                        new_descriptor_low_pages[page] = pa
                else:
                    pa = resolve_firmware_page(page)
                destination[page] = int(pa)

    queue_context_pages = {}
    scheduler_pages = {}
    channel_ring_pages = {}
    for ordinal in range(start_ordinal, count + 1):
        submission = submission_for_ordinal(ordinal)
        work_index = ordinal - 1
        for address, destination in (
            (
                addresses["queue_context"]
                + g17g_compute.compute_queue_context_item_offset(work_index),
                queue_context_pages,
            ),
            (submission["scheduler"], scheduler_pages),
            (
                addresses["channel_ring"]
                + g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
                + g17g_backend.compute_channel_slot_index(ordinal)
                * g17g.RING_SLOT_SIZE,
                channel_ring_pages,
            ),
        ):
            page = int(address) & ~(PAGE_SIZE - 1)
            if page not in destination:
                destination[page] = resolve_firmware_page(page)

    new_tables = tuple(
        sorted(set(map(int, uat.dirty)) - dirty_before)
    )
    uat.flush_dirty()
    uat.invalidate_cache()
    uat.invalidate_root_walk_cache()

    publications = []
    publish_pages = set(new_tables)
    publish_pages.update(buffer_pas.values())
    publish_pages.update(new_client_pages.values())
    publish_pages.update(new_descriptor_low_pages.values())
    publish_pages.update(recreated_pages.values())
    output_records = []

    def add_publication(pa, body):
        publications.append((int(pa), bytes(body)))
        first_page = int(pa) & ~(PAGE_SIZE - 1)
        last_page = (int(pa) + len(body) - 1) & ~(PAGE_SIZE - 1)
        publish_pages.update(range(first_page, last_page + 1, PAGE_SIZE))

    def add_firmware_publication(dva, body):
        """Append one firmware-DVA write as physical page fragments."""
        dva = int(dva)
        body = bytes(body)
        body_offset = 0
        while body_offset < len(body):
            virtual = dva + body_offset
            page = virtual & ~(PAGE_SIZE - 1)
            page_offset = virtual - page
            length = min(
                PAGE_SIZE - page_offset, len(body) - body_offset
            )
            add_publication(
                resolve_firmware_page(page) + page_offset,
                body[body_offset:body_offset + length],
            )
            body_offset += length

    retired_queue_tombstones = []
    if recycled_queue_epoch is not None:
        # Reusing a drained transport's backing is not teardown.  The global
        # queue-context array and channel-8 outer ring still name the old
        # queue after its counters have converged.  Clear those ownership
        # edges before publishing a new generation at the same queue DVA.
        # This is the first ordered subset of the completed Neo teardown
        # model; the retired scheduler/queue-local objects are zeroed above.
        retired_start = g17g_backend.compute_queue_start_ordinal(
            recycled_queue_epoch
        )
        retired_count = g17g_backend.compute_queue_command_capacity(
            recycled_queue_epoch
        )
        retired_queue = g17g_backend.compute_recreated_queue_addresses(
            recycled_queue_epoch
        )["queue"]
        retired_context = (
            addresses["queue_context"]
            + 0x200
            + (retired_start - 1) * 0x200
        )
        retired_channel = (
            addresses["channel_ring"]
            + g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
            + (retired_start - 1) * g17g.RING_SLOT_SIZE
        )
        add_firmware_publication(
            retired_context, bytes(retired_count * 0x200)
        )
        add_firmware_publication(
            retired_channel,
            bytes(retired_count * g17g.RING_SLOT_SIZE),
        )
        retired_queue_tombstones.append({
            "queue_epoch": recycled_queue_epoch,
            "queue": retired_queue,
            "queue_context_range": [
                retired_context,
                retired_context + retired_count * 0x200,
            ],
            "channel_ring_range": [
                retired_channel,
                retired_channel + retired_count * g17g.RING_SLOT_SIZE,
            ],
        })

    scheduler_wave_reset = bool(
        queue_epoch and not recreate_transport
    )
    if scheduler_wave_reset:
        # A later compute queue accepts a bounded 20-record scheduler wave per
        # kick.  All preceding work is quiescent here, so rebuild the empty
        # intrusive head and clear the reusable records/ready words before
        # publishing this wave.  The queue, item ring and pointer producer
        # continue at their existing cumulative positions.
        job_list_body = bytearray(PAGE_SIZE)
        struct.pack_into("<Q", job_list_body, 0x08, addresses["job_list"])
        add_firmware_publication(
            addresses["scheduler"], bytes(2 * PAGE_SIZE)
        )
        add_firmware_publication(addresses["job_list"], job_list_body)
        add_firmware_publication(
            addresses["scheduler_slot"], bytes(PAGE_SIZE)
        )

    for ordinal in range(start_ordinal, count + 1):
        submission = submission_for_ordinal(ordinal)
        client = (
            {
                "shader": g17g_backend.COMPUTE_MIXED_SHADER,
                "cdm": g17g_backend.COMPUTE_MIXED_CDM,
                "resource": g17g_backend.COMPUTE_MIXED_RESOURCE,
            }
            if reuse_queue_group else
            g17g_backend.compute_client_submission_addresses(ordinal)
        )
        buffers = buffer_addresses_for_ordinal(ordinal)
        queue_local_index = ordinal - transport_start_ordinal
        work_index = ordinal - 1
        values_a = tuple(
            float(ordinal * 1000 + index) for index in range(64)
        )
        values_b = (float(ordinal) - 0.75,) * 64
        expected = tuple(
            left + right for left, right in zip(values_a, values_b)
        )
        add_publication(
            buffer_pas[(ordinal, "a")], struct.pack("<64f", *values_a)
        )
        add_publication(
            buffer_pas[(ordinal, "b")], struct.pack("<64f", *values_b)
        )
        add_publication(buffer_pas[(ordinal, "out")], bytes(PAGE_SIZE))

        shader = g17g_compute.relocate_add_shader(
            g17g_backend.COMPUTE_SHADER, client["shader"]
        )
        cdm = g17g_compute.build_cdm_stream((
            g17g_compute.build_direct_dispatch(
                client["shader"], (64, 1, 1), (32, 1, 1)
            ),
        ))
        resource = g17g_compute.build_buffer_resource_table(
            (buffers["a"], buffers["b"], buffers["out"]),
            size=g17g_backend.COMPUTE_RESOURCE_SIZE,
        )
        add_publication(context1["ram_pages"][client["shader"]], shader)
        add_publication(context1["ram_pages"][client["cdm"]], cdm)
        add_publication(
            context1["ram_pages"][client["resource"]], resource
        )

        scheduler_slot_index = (
            ordinal - start_ordinal + 1
            if queue_epoch else
            g17g_backend.compute_scheduler_slot_index(ordinal)
        )
        scheduler = g17g_compute.build_compute_scheduler_record(
            addresses["scheduler_slot"],
            slot_index=scheduler_slot_index,
            # In the coherent mixed stream the intervening render consumes
            # global work ID 1, so the second compute owns ID 2.  Ordinary
            # compute-only streams retain their zero-based local work IDs.
            work_id=(ordinal if reuse_queue_group else work_index),
        )
        registers = g17g_compute.build_compute_registers(
            resource=client["resource"],
            cdm=client["cdm"],
            robustness=submission["robustness"],
            scratch=scratch_address,
            dispatch_identity=submission["dispatch_identity"],
            # The packed register work byte belongs to the current queue;
            # global submission identity is carried separately below.
            # The mixed compute queue's register program carries the global
            # engine-work ordinal, including the intervening render.  Its
            # second native dispatch therefore encodes 0x102 in registers
            # 0x10201/0x10428, even though it is only queue-local command 1.
            work_ordinal=(ordinal if reuse_queue_group else queue_local_index),
        )
        descriptor = g17g_compute.build_compute_descriptor(
            registers=registers,
            scheduler_record=submission["scheduler"],
            low_alias=submission["descriptor_low"],
            cdm_terminator=client["cdm"] + len(cdm) - 4,
            dispatch_identity=submission["dispatch_identity"],
            submit_sequence=queue_local_index,
            context_id=1,
            # Native queue zero and the earliest materialized queue one both
            # retain descriptor index zero.  Queue creation is carried by the
            # queue record, selector-15 and dispatch-identity transition.
            descriptor_index=0,
            lifecycle_ordinal=ordinal,
            queue_submission=queue_local_index + 1,
            # Preserve the sustained standalone profile that predates the
            # mixed fresh-queue default at +f58. Mixed profiles stay explicit.
            queue_ordinal=(None if reuse_queue_group or graph_profile.get("format") in (
                "m1n1-t8142-g17g-host-mixed-compute-graph-v1",
                "m1n1-t8142-g17g-host-mixed-compute-graph-v2",
            ) else 0),
            dispatch_a=addresses["dispatch_a"],
            dispatch_b=addresses["dispatch_b"],
            status_a=submission["status_a"],
            status_b=submission["status_b"],
            shared_control=descriptor_control,
            zero_page=submission["zero_page"],
        )[:descriptor_size]
        for alias_address, pages in (
            (submission["descriptor"], descriptor_high_pages),
            (submission["descriptor_low"], descriptor_low_pages),
        ):
            body_offset = 0
            while body_offset < len(descriptor):
                virtual = alias_address + body_offset
                page = virtual & ~(PAGE_SIZE - 1)
                page_offset = virtual - page
                length = min(
                    PAGE_SIZE - page_offset, len(descriptor) - body_offset
                )
                add_publication(
                    pages[page] + page_offset,
                    descriptor[body_offset:body_offset + length],
                )
                body_offset += length

        scheduler_address = submission["scheduler"]
        scheduler_page = scheduler_address & ~(PAGE_SIZE - 1)
        add_publication(
            scheduler_pages[scheduler_page]
            + scheduler_address - scheduler_page,
            scheduler,
        )
        add_publication(
            scheduler_slot_pa + scheduler_slot_index * 4,
            struct.pack("<I", 1),
        )
        add_publication(
            compute_page_pa(submission["status_a"], plan, postcontrol),
            bytes(8),
        )
        add_publication(
            compute_page_pa(submission["status_b"], plan, postcontrol),
            bytes(8),
        )
        event = g17g_compute.build_compute_event(
            group_number=ordinal, generation=2
        )
        add_publication(
            compute_page_pa(submission["event"], plan, postcontrol), event
        )
        # The initial graph owns one 16-KiB zero/robustness record page.  Both
        # 0x40-stride arenas grow at command 257; install fresh zero firmware
        # leaves on demand just as the client robustness page is grown above.
        add_firmware_publication(submission["zero_page"], bytes(0x40))
        if reuse_queue_group:
            item_start = 3 * (ordinal - 1)
            item_limit = item_start + 3
            add_firmware_publication(
                submission["optional"],
                g17g_compute.build_compute_optional(
                    g17g_backend.COMPUTE_MIXED_QUEUE_CONTEXT_LOW,
                    addresses["queue_context"],
                    shared_control=addresses["shared_support"],
                    channel_control=addresses["queue_aux"],
                    submission_ordinal=item_start,
                    token=int(graph_profile.get(
                        "queue_generation",
                        g17g_compute.COMPUTE_QUEUE_GENERATION,
                    )),
                    first_queue=False,
                    queue_index=int(graph_profile.get("queue_index", 0)),
                    byte_46=0,
                ),
            )
            item_publications = [
                (item_start, submission["optional"]),
                (item_start + 1, submission["descriptor"]),
                (item_start + 2, submission["event"]),
            ]
        else:
            item_start = 1 + 2 * queue_local_index
            item_limit = item_start + 2
            item_publications = [
                (item_start, submission["descriptor"]),
                (item_start + 1, submission["event"]),
            ]
        if recreate_transport:
            item_publications.insert(0, (0, addresses["optional"]))
        for logical_item_index, item_address in item_publications:
            add_publication(
                item_ring_pa
                + (
                    logical_item_index
                    % g17g_compute.COMPUTE_ITEM_RING_ENTRY_COUNT
                ) * g17g.ITEM_RING_ENTRY_SIZE,
                struct.pack("<Q", item_address),
            )
        channel_slot_address = (
            addresses["channel_ring"]
            + g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
            + g17g_backend.compute_channel_slot_index(ordinal)
            * g17g.RING_SLOT_SIZE
        )
        channel_slot_page = channel_slot_address & ~(PAGE_SIZE - 1)
        add_publication(
            channel_ring_pages[channel_slot_page]
            + channel_slot_address - channel_slot_page,
            (
                g17g_compute.build_compute_full_group_channel_slot(
                    addresses["queue"], item_limit=item_limit
                )
                if reuse_queue_group else
                g17g_compute.build_compute_channel_slot(addresses["queue"])
                if recreate_transport and queue_local_index == 0 else
                g17g_compute.build_compute_repeat_channel_slot(
                    addresses["queue"], item_limit=item_limit
                )
            ),
        )
        queue_context_address = (
            addresses["queue_context"]
            + g17g_compute.compute_queue_context_item_offset(
                work_index
            )
        )
        queue_context_page = queue_context_address & ~(PAGE_SIZE - 1)
        add_publication(
            queue_context_pages[queue_context_page]
            + queue_context_address - queue_context_page,
            g17g_compute.build_compute_queue_context_item(
                submission["descriptor"],
                addresses["queue"],
                item_index=queue_local_index,
            ),
        )
        output_records.append({
            "ordinal": ordinal,
            "dva": buffers["out"],
            "pa": buffer_pas[(ordinal, "out")],
            "expected": expected,
        })

    if reuse_queue_group:
        # The native second-compute publication resets both completion words
        # from compute one and advances the containing status cohort to two.
        # Merely redirecting descriptor two to the older zero pair leaves the
        # shared scheduler status at the post-compute-one image.
        add_firmware_publication(
            g17g_backend.COMPUTE_GLOBAL_STATUS_A - 0x08,
            struct.pack("<5Q", 2, 0, 0, 0, 0),
        )

    if recreate_transport:
        add_publication(
            recreated_pages[addresses["queue_support"]],
            g17g_compute.build_compute_shared_support(
                g17g_backend.COMPUTE_CLIENT_STATE,
                previous_pointer_address,
                active=start_ordinal,
            ),
        )
        add_publication(
            resolve_firmware_page(addresses["optional"]),
            g17g_compute.build_compute_optional(
                queue_context_low,
                addresses["queue_context"],
                shared_control=descriptor_control,
                channel_control=addresses["queue_aux"],
                submission_ordinal=start_ordinal,
                token=queue_generation,
                first_queue=False,
            ),
        )
        add_publication(
            queue_pa,
            g17g_compute.build_compute_queue_record(
                addresses["pointers"],
                addresses["item_ring"],
                addresses["job_list"],
                addresses["queue_aux"],
                queue_generation=queue_generation,
            ),
        )
    elif queue_epoch:
        # Descriptors on recreated queues reference this queue-local support
        # object, not the original global support page.  Its first qword is
        # the active global command high-water mark and must advance before
        # each later kick just like the original queue's support counter.
        add_publication(
            active_page_pa(addresses["queue_support"]),
            struct.pack("<Q", count),
        )

    if reuse_queue_group:
        mixed_shared_state = bytearray(0x40)
        struct.pack_into("<I", mixed_shared_state, 0, count)
        add_publication(shared_state_pa, mixed_shared_state)
        add_publication(
            shared_support_pa + 0x20,
            struct.pack("<Q", 0x0000166000000060),
        )
    else:
        add_publication(shared_state_pa, struct.pack("<I", count))
    add_publication(shared_support_pa, struct.pack("<Q", count))
    add_publication(
        shared_support_pa + 0x40,
        struct.pack("<Q", 0 if reuse_queue_group else count << 32),
    )
    write_count = write_physical_publications(publications)
    published_body_pages = publish_coprocessor_pages(
        publish_pages,
        include_coprocessor_sys=include_coprocessor_sys,
    )

    final_item_limit = (
        3 * count if reuse_queue_group else
        2 * (count - transport_start_ordinal + 1) + 1
    )
    pointer_release = (
        g17g_backend.build_mixed_compute_pointer_release(
            completed_item_limit, final_item_limit
        )
        if reuse_queue_group else
        g17g.build_pointer_block(
            field_00=0, field_30=0, field_40=final_item_limit
        )
        if recreate_transport else
        struct.pack("<I", final_item_limit)
    )
    pointer_release_pa = (
        pointer_pa
        if recreate_transport or reuse_queue_group else
        pointer_pa + g17g.POINTER_FIELD_40
    )
    write_physical_publications((
        (pointer_release_pa, pointer_release),
        (
            state_pa + g17g_compute.COMPUTE_CHANNEL_STATE_OFFSET + 0x20,
            struct.pack(
                "<I", g17g_backend.compute_channel_counter(count)
            ),
        ),
    ))
    published_release_pages = publish_coprocessor_pages(
        (pointer_pa, state_pa),
        include_coprocessor_sys=include_coprocessor_sys,
    )
    u.inst("tlbi aside1os, x0", 1 << 48)
    u.inst("tlbi aside1os, x0", POSTCONTROL_CONTEXT_ID << 48)
    u.inst("dsb sy")

    lifecycle_published = lifecycle_state()
    published_channel_counter = g17g_backend.compute_channel_counter(count)
    if lifecycle_published["channel"] != [
        completed_channel_counter,
        completed_channel_counter,
        published_channel_counter,
    ]:
        raise RuntimeError(
            "compute batch producer did not publish: %r"
            % lifecycle_published["channel"]
        )
    expected_pointer = (
        (completed_item_limit, completed_item_limit, final_item_limit)
        if reuse_queue_group else None
    )
    observed_pointer = tuple(
        lifecycle_published["pointer"][name]
        for name in ("field_00", "field_30", "field_40")
    )
    if (
        observed_pointer != expected_pointer
        if expected_pointer is not None else
        lifecycle_published["pointer"]["field_40"] != final_item_limit
    ):
        raise RuntimeError("compute batch pointer producer did not publish")
    if recreate_transport and (
        lifecycle_published["pointer"]["field_00"],
        lifecycle_published["pointer"]["field_30"],
        lifecycle_published["queue"]["limit_1c"],
    ) != (0, 0, 0):
        raise RuntimeError(
            "compute recreated transport did not reset its consumers"
        )
    repeat_prework_snapshot = None
    repeat_prework_oracle = None
    if reuse_queue_group and args.mixed_compute_prework_oracle_at_repeat:
        repeat_prework_oracle = apply_mixed_compute_prework_oracle(
            uat,
            root_pa,
            context1,
            plan,
            postcontrol,
            fresh_firmware_pages,
            coherent_peer_output_dva=coherent_render_target_dva,
            prior_firmware_pages=prior_firmware_pages,
        )
        # Topology closure may split a source physical alias while retaining
        # the command's DVA.  Rebind every observation to the now-active leaf
        # instead of reading the pre-oracle source PA after the work kick.
        for output_record in output_records:
            output_record["pa"] = int(
                context1["ram_pages"][int(output_record["dva"])]
            )
            if any(read_physical(output_record["pa"], PAGE_SIZE)):
                raise RuntimeError(
                    "repeat-boundary native compute output is not zero"
                )
        state_pa = active_page_pa(addresses["state"])
        queue_pa = active_page_pa(addresses["queue"])
        pointer_pa = active_page_pa(addresses["pointers"])
        item_ring_pa = active_page_pa(addresses["item_ring"])
        channel_ring_pa = active_page_pa(addresses["channel_ring"])
        shared_state_pa = active_page_pa(addresses["shared_state"])
        shared_support_pa = active_page_pa(addresses["shared_support"])
        scheduler_slot_pa = active_page_pa(addresses["scheduler_slot"])
    if reuse_queue_group and args.capture_mixed_repeat_prework:
        repeat_prework_snapshot = capture_compute_prework_state(
            root_pa,
            context1,
            plan,
            postcontrol,
            fresh_firmware_pages,
            operation="mixed_repeat_compute",
            retired_addresses=tuple(
                address
                for address in g17g_backend.RENDER_SOURCE_RETIRED_GLOBAL_PAGES
                if uat.iotranslate_root(
                    root_pa, address, PAGE_SIZE
                ) == [(None, PAGE_SIZE)]
            ),
            boundary=(
                "after publishing source compute two; before its "
                "type-0x83 work notification"
            ),
        )

    events_before = {
        asc.coldboot_name: len(asc.fw.events) for asc in asces
    }
    print(
        "Publishing compute groups %d..%d in one batch and sending one "
        "primary type-0x83 %#x" % (start_ordinal, count, work_message)
    )
    asces[0].send(work_message, ASCMessage1(EP=0x21))
    deadline = time.monotonic() + args.compute_wait_ms / 1000.0
    # Do not download the entire multi-megabyte backing allocation on every
    # poll. Commands retire in publication order, so the final command's first
    # exact float is a compact convergence witness. Validate every output with
    # one full read only after that witness changes (or at the deadline).
    final_output = output_records[-1]
    final_probe = struct.pack("<f", final_output["expected"][0])
    final_probe_count = 0
    final_probe_exact = False
    while time.monotonic() < deadline:
        observe_asces(asces, 0.01)
        final_probe_count += 1
        final_probe_exact = (
            read_physical(final_output["pa"], len(final_probe))
            == final_probe
        )
        if final_probe_exact:
            break
    output_bodies = {
        output_record["pa"]: read_physical(
            output_record["pa"], PAGE_SIZE
        )
        for output_record in output_records
    }
    exact_count = 0
    for output_record in output_records:
        actual = struct.unpack_from(
            "<64f", output_bodies[output_record["pa"]]
        )
        if actual == output_record["expected"]:
            exact_count += 1
    lifecycle_after = lifecycle_state()
    outputs = []
    for record in output_records:
        body = output_bodies[record["pa"]]
        actual = struct.unpack_from("<64f", body)
        outputs.append({
            "ordinal": record["ordinal"],
            "dva": record["dva"],
            "pa": record["pa"],
            "changed": any(body),
            "exact_first_64_floats": actual == record["expected"],
            "sha256": sha256(body),
        })
    record = {
        "format": "m1n1-t8142-g17g-source-compute-batch-v1",
        "captured_input": None,
        "count": count,
        "batched_ordinal_range": [start_ordinal, count],
        "independent_output_count": len(outputs),
        "exact_output_count": exact_count,
        "all_outputs_exact": exact_count == command_count,
        "single_work_kick": True,
        "final_probe_count": final_probe_count,
        "final_probe_exact": final_probe_exact,
        "transport_recreated": recreate_transport,
        "recreated_after_fault": recreate_after_fault,
        "queue_epoch": queue_epoch,
        "transport_start_ordinal": transport_start_ordinal,
        "transport_addresses": addresses,
        "retired_queue_tombstones": retired_queue_tombstones,
        "scheduler_wave_reset": scheduler_wave_reset,
        "context_local_buffer_reuse": reuse_context_buffers,
        "queue_group_reused": reuse_queue_group,
        "repeat_prework_oracle": repeat_prework_oracle,
        "repeat_prework_snapshot": repeat_prework_snapshot,
        "physical_scatter_write_count": write_count,
        "new_context1_page_count": (
            (0 if reuse_context_buffers else len(buffer_pas))
            + len(new_client_pages)
            + len(new_descriptor_low_pages)
        ),
        "lifecycle_before": lifecycle_before,
        "lifecycle_published": lifecycle_published,
        "lifecycle_after": lifecycle_after,
        "outputs": outputs,
        "published_body_pages": list(published_body_pages),
        "published_release_pages": list(published_release_pages),
        "firmware_event_count_delta": {
            asc.coldboot_name: (
                len(asc.fw.events) - events_before[asc.coldboot_name]
            )
            for asc in asces
        },
        "execution_claim": (
            "compute-batch" if exact_count == command_count else "none"
        ),
    }
    encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    output_path = attempt_dir / (
        "compute_output_batch_%04d_%04d.json" % (start_ordinal, count)
    )
    output_path.write_bytes(encoded)
    record["file"] = output_path.name
    record["sha256"] = sha256(encoded)
    if exact_count != command_count and not allow_inexact:
        raise RuntimeError(
            "source compute batch produced %d/%d exact outputs"
            % (exact_count, command_count)
        )
    print(
        "SOURCE COMPUTE BATCH: %s, %d/%d independent target pages "
        "changed with exact sums" % (
            "EXECUTED" if exact_count == command_count else "INEXACT",
            exact_count,
            command_count,
        )
    )
    return record
