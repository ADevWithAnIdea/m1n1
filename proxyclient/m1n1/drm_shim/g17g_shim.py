# SPDX-License-Identifier: GPL-2.0-only
"""T8142/G17G backend boundary shared by experiments and ``drm_shim``.

The cold-boot runtime owns allocation, UAT publication, cache maintenance and
mailbox transport. This object owns the caller-facing compute operation and
the clean-room graph it submits, so the hardware experiment and ``drm_shim``
cannot diverge into separate submission implementations.
"""

from . import g17g, g17g_backend, g17g_sync


class G17GUnsupported(RuntimeError):
    """The requested operation is not implemented by the G17G backend."""


class G17GShimBackend:
    """One live source-built G17G world, as consumed by ``DRMAsahiShim``.

    ``submit_compute`` accepts a graph returned by
    :func:`g17g_backend.build_add_compute_graph` and returns the runtime's
    execution record.  Render queues are host-only ordering domains
    multiplexed onto one paired firmware transport.  The runtime adapter owns
    the decoded per-work allocation and retirement lifecycle; logical queue
    IDs never become firmware queue-grid indices.
    """

    def __init__(self, submit_compute=None, submit_render=None,
                 compute_graph_builder=None):
        if submit_compute is not None and not callable(submit_compute):
            raise TypeError("G17G submit_compute adapter must be callable")
        if submit_render is not None and not callable(submit_render):
            raise TypeError("G17G submit_render adapter must be callable")
        if (
            compute_graph_builder is not None
            and not callable(compute_graph_builder)
        ):
            raise TypeError("G17G compute graph builder must be callable")
        if submit_compute is None and submit_render is None:
            raise TypeError("G17G backend needs a compute or render adapter")
        self._submit_compute = submit_compute
        self._submit_render = submit_render
        self._compute_graph_builder = (
            g17g_backend.build_add_compute_graph
            if compute_graph_builder is None else compute_graph_builder
        )
        self.last_compute = None
        self.last_render = None
        self.compute_submissions = []
        self.render_submissions = []
        self._compute_queues = {
            0: {
                "submission_count": 0,
                "priority": g17g.UAPI_QUEUE_PRIORITY_MEDIUM,
                "firmware_priority": 2,
            }
        }
        self._destroyed_compute_queues = {}
        self._next_compute_queue_id = 1
        self._compute_submission_count = 0
        self._render_queues = {
            0: {
                "submission_count": 0,
                "priority": g17g.UAPI_QUEUE_PRIORITY_MEDIUM,
                "firmware_priority": 2,
            }
        }
        self._destroyed_render_queues = {}
        self._next_render_queue_id = 1
        self._render_submission_count = 0
        self._execution_contexts = {
            0: {"compute_submission_count": 0, "render_submission_count": 0}
        }
        self._destroyed_execution_contexts = {}
        self._next_execution_context_id = 1
        self._completion_sequence = 0
        self.submission_fences = []
        self.last_fence = None
        self.fence_tracker = g17g_sync.G17GFenceTracker()
        self.faults = []
        self.last_fault = None
        self._device_lost = None

    def create_execution_context(self):
        """Create one host VM to be serialized through admitted context 1."""
        context_id = self._next_execution_context_id
        self._next_execution_context_id += 1
        self._execution_contexts[context_id] = {
            "compute_submission_count": 0,
            "render_submission_count": 0,
        }
        return context_id

    def destroy_execution_context(self, context_id):
        """Destroy a synchronously quiescent nondefault execution context."""
        context_id = int(context_id)
        if context_id == 0:
            raise G17GUnsupported(
                "the default G17G execution context is permanent"
            )
        if context_id in self._destroyed_execution_contexts:
            return dict(self._destroyed_execution_contexts[context_id])
        state = self._execution_contexts.get(context_id)
        if state is None:
            raise G17GUnsupported("unknown G17G execution context")
        tombstone = {
            "context_id": context_id,
            "compute_submission_count": int(
                state["compute_submission_count"]
            ),
            "render_submission_count": int(
                state["render_submission_count"]
            ),
            "firmware_context_id": 1,
            "quiescent": True,
        }
        del self._execution_contexts[context_id]
        self._destroyed_execution_contexts[context_id] = tombstone
        return dict(tombstone)

    def execution_context_state(self, context_id):
        """Return caller-visible context accounting without exposing roots."""
        context_id = int(context_id)
        state = self._execution_contexts.get(context_id)
        if state is None:
            if context_id in self._destroyed_execution_contexts:
                raise G17GUnsupported("destroyed G17G execution context")
            raise G17GUnsupported("unknown G17G execution context")
        return {
            "context_id": context_id,
            "compute_submission_count": int(
                state["compute_submission_count"]
            ),
            "render_submission_count": int(
                state["render_submission_count"]
            ),
            "firmware_context_id": 1,
        }

    def _execution_context(self, context_id):
        context_id = int(context_id)
        state = self._execution_contexts.get(context_id)
        if state is None:
            if context_id in self._destroyed_execution_contexts:
                raise G17GUnsupported("destroyed G17G execution context")
            raise G17GUnsupported("unknown G17G execution context")
        return context_id, state

    def _ensure_device_available(self):
        if self._device_lost is not None:
            raise G17GUnsupported(
                "G17G device was lost after %s"
                % self._device_lost["kind"]
            )

    @staticmethod
    def _assert_queue_usable(queue, engine, queue_id):
        fault = queue.get("terminal_fault")
        if fault is not None:
            raise G17GUnsupported(
                "faulted G17G %s queue %d (%s)"
                % (engine, int(queue_id), fault["kind"])
            )

    def fault_state(self):
        """Return immutable fault/device-loss state for UAPI diagnostics."""
        return {
            "device_lost": self._device_lost is not None,
            "last_fault": (
                None if self.last_fault is None else dict(self.last_fault)
            ),
            "fault_count": len(self.faults),
        }

    @staticmethod
    def _queue_priority(priority):
        priority = int(priority)
        try:
            return g17g.uapi_queue_priority_profile(priority)
        except ValueError as exc:
            raise G17GUnsupported(str(exc)) from exc

    @staticmethod
    def _queue_object_name(name):
        """Return whether *name* is an actual queue-record page.

        ``queue_context`` and ``queue_aux`` are unrelated structures whose
        names happen to share the prefix.  Fresh per-publication queue pages
        use only ``queue_<decimal>``.
        """
        if name == "queue":
            return True
        prefix = "queue_"
        return name.startswith(prefix) and name[len(prefix):].isdigit()

    @staticmethod
    def _retarget_queue_object(body, priority, all_records=True):
        """Apply a priority to the active 0x80-byte record(s) in a blob."""
        body = bytes(body)
        if len(body) < g17g.QUEUE_RECORD_SIZE:
            raise ValueError("G17G queue object is shorter than one record")
        data = bytearray(body)
        count = 0
        offsets = (
            range(
                0, len(data) - g17g.QUEUE_RECORD_SIZE + 1,
                g17g.QUEUE_RECORD_STRIDE,
            )
            if all_records else (0,)
        )
        for offset in offsets:
            record = bytes(data[offset:offset + g17g.QUEUE_RECORD_SIZE])
            if not any(record[:g17g.QUEUE_ADDRESS_10_OFFSET + 8]):
                continue
            data[offset:offset + g17g.QUEUE_RECORD_SIZE] = (
                g17g.apply_queue_priority(record, priority)
            )
            count += 1
        if not count:
            raise ValueError("G17G queue object contains no populated record")
        return bytes(data), count

    @classmethod
    def _retarget_submission_priority(cls, submission, priority):
        """Copy and retarget every explicit queue object in one graph."""
        submission = dict(submission)
        object_key = (
            "firmware_pages" if "firmware_pages" in submission else
            "firmware_objects" if "firmware_objects" in submission else None
        )
        if object_key is None:
            raise ValueError("G17G submission has no firmware queue objects")
        objects = dict(submission[object_key])
        count = 0
        for name, body in tuple(objects.items()):
            if not cls._queue_object_name(name):
                continue
            # Compute's opening queue page retains a second, populated
            # post-control record that is not the active channel-8 queue.  Its
            # native profile is 0 even while the selected compute record is
            # profile 2.  Fresh compute queue_N objects likewise put their one
            # active record at offset zero.  Render's queue page instead holds
            # the active paired TA/fragment records, so both are retargeted.
            objects[name], changed = cls._retarget_queue_object(
                body, priority, all_records=(object_key == "firmware_pages")
            )
            count += changed
        if not count:
            raise ValueError("G17G submission contains no named queue record")
        submission[object_key] = objects
        submission["firmware_priority"] = int(priority)
        submission["firmware_priority_record_count"] = count
        return submission

    def create_compute_queue(self, priority=g17g.UAPI_QUEUE_PRIORITY_MEDIUM):
        """Create a host ordering domain on the shared compute transport."""
        profile = self._queue_priority(priority)
        queue_id = self._next_compute_queue_id
        self._next_compute_queue_id += 1
        self._compute_queues[queue_id] = {
            "submission_count": 0,
            "priority": int(profile["uapi_priority"]),
            "firmware_priority": int(profile["firmware_priority"]),
        }
        return queue_id

    def destroy_compute_queue(self, queue_id):
        """Destroy a synchronously quiescent host compute queue."""
        queue_id = int(queue_id)
        if queue_id == 0:
            raise G17GUnsupported("the default G17G compute queue is permanent")
        if queue_id in self._destroyed_compute_queues:
            return dict(self._destroyed_compute_queues[queue_id])
        state = self._compute_queues.get(queue_id)
        if state is None:
            raise G17GUnsupported("unknown G17G compute queue")
        tombstone = {
            "queue_id": queue_id,
            "submission_count": int(state["submission_count"]),
            "priority": int(state["priority"]),
            "firmware_priority": int(state["firmware_priority"]),
            "firmware_transport": "shared-compute",
            "quiescent": True,
        }
        del self._compute_queues[queue_id]
        self._destroyed_compute_queues[queue_id] = tombstone
        return dict(tombstone)

    def compute_queue_state(self, queue_id):
        """Return immutable logical-queue accounting for diagnostics."""
        queue_id = int(queue_id)
        state = self._compute_queues.get(queue_id)
        if state is None:
            if queue_id in self._destroyed_compute_queues:
                raise G17GUnsupported("destroyed G17G compute queue")
            raise G17GUnsupported("unknown G17G compute queue")
        return {
            "queue_id": queue_id,
            "submission_count": int(state["submission_count"]),
            "priority": int(state["priority"]),
            "firmware_priority": int(state["firmware_priority"]),
            "firmware_transport": "shared-compute",
        }

    def create_render_queue(self, priority=g17g.UAPI_QUEUE_PRIORITY_MEDIUM):
        """Create a host ordering domain on the shared render transport."""
        profile = self._queue_priority(priority)
        queue_id = self._next_render_queue_id
        self._next_render_queue_id += 1
        self._render_queues[queue_id] = {
            "submission_count": 0,
            "priority": int(profile["uapi_priority"]),
            "firmware_priority": int(profile["firmware_priority"]),
        }
        return queue_id

    def destroy_render_queue(self, queue_id):
        """Destroy a synchronously quiescent host render queue."""
        queue_id = int(queue_id)
        if queue_id == 0:
            raise G17GUnsupported("the default G17G render queue is permanent")
        if queue_id in self._destroyed_render_queues:
            return dict(self._destroyed_render_queues[queue_id])
        state = self._render_queues.get(queue_id)
        if state is None:
            raise G17GUnsupported("unknown G17G render queue")
        tombstone = {
            "queue_id": queue_id,
            "submission_count": int(state["submission_count"]),
            "priority": int(state["priority"]),
            "firmware_priority": int(state["firmware_priority"]),
            "firmware_transport": "shared-paired-render",
            "quiescent": True,
        }
        del self._render_queues[queue_id]
        self._destroyed_render_queues[queue_id] = tombstone
        return dict(tombstone)

    def render_queue_state(self, queue_id):
        """Return immutable logical-queue accounting for diagnostics."""
        queue_id = int(queue_id)
        state = self._render_queues.get(queue_id)
        if state is None:
            if queue_id in self._destroyed_render_queues:
                raise G17GUnsupported("destroyed G17G render queue")
            raise G17GUnsupported("unknown G17G render queue")
        return {
            "queue_id": queue_id,
            "submission_count": int(state["submission_count"]),
            "priority": int(state["priority"]),
            "firmware_priority": int(state["firmware_priority"]),
            "firmware_transport": "shared-paired-render",
        }

    def _submit_render_products(self, products, queue_id, context_id):
        self._ensure_device_available()
        if self._submit_render is None:
            raise G17GUnsupported("G17G render adapter is unavailable")
        context_id, context = self._execution_context(context_id)
        queue_id = int(queue_id)
        queue = self._render_queues.get(queue_id)
        if queue is None:
            if queue_id in self._destroyed_render_queues:
                raise G17GUnsupported("destroyed G17G render queue")
            raise G17GUnsupported("unknown G17G render queue")
        self._assert_queue_usable(queue, "render", queue_id)

        # This envelope is consumed only by the host runtime.  In particular,
        # logical_queue_id must not be encoded into queue record grid fields:
        # native MTLCommandQueues share the same paired TA/fragment transport.
        submission = self._retarget_submission_priority(
            products, queue["firmware_priority"]
        )
        submission.update({
            "logical_queue_id": queue_id,
            "logical_queue_sequence": int(queue["submission_count"]),
            "logical_global_sequence": self._render_submission_count,
            "logical_context_id": context_id,
            "logical_context_sequence": int(
                context["render_submission_count"]
            ),
            "firmware_context_id": 1,
            "firmware_transport": "shared-paired-render",
            "priority": int(queue["priority"]),
            "firmware_priority": int(queue["firmware_priority"]),
        })
        result = self._submit_render(submission)
        if result.get("captured_input") is not None:
            raise RuntimeError("G17G render backend accepted captured input")

        return result, submission

    def _commit_render_submission(self, queue_id, submission, result):
        queue_id = int(queue_id)
        queue = self._render_queues.get(queue_id)
        if queue is None:
            if queue_id in self._destroyed_render_queues:
                raise G17GUnsupported("destroyed G17G render queue")
            raise G17GUnsupported("unknown G17G render queue")

        queue["submission_count"] += 1
        self._execution_contexts[
            submission["logical_context_id"]
        ]["render_submission_count"] += 1
        self._render_submission_count += 1
        self.render_submissions.append({
            "logical_queue_id": queue_id,
            "logical_queue_sequence": submission["logical_queue_sequence"],
            "logical_global_sequence": submission["logical_global_sequence"],
            "execution_claim": result.get("execution_claim"),
        })
        self.last_render = result

    @staticmethod
    def _validate_partial_result(result):
        if result.get("execution_claim") not in (
            "partial-render", "partial-render-repeat",
            "partial-render-repeat-stream",
        ):
            raise RuntimeError(
                "G17G backend lacks a partial-render execution proof"
            )
        if not result.get("changed"):
            raise RuntimeError(
                "G17G partial render did not change its attachments"
            )
        if not result.get("exact_partial_attachments"):
            raise RuntimeError(
                "G17G partial-render attachments do not match expected output"
            )
        attachments = result.get("attachments", ())
        if len(attachments) != g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT:
            raise RuntimeError("G17G partial-render output set is incomplete")
        if not all(
            attachment.get("changed")
            and attachment.get(
                "exact_expected_output",
                attachment.get("exact_native_output"),
            )
            for attachment in attachments
        ):
            raise RuntimeError(
                "G17G partial-render expected-output proof is incomplete"
            )

    def submit_add(
        self, values_a=None, values_b=None, queue_id=0, context_id=0,
    ):
        """Submit direct-CDM vector add and require exact output mutation."""
        self._ensure_device_available()
        if self._submit_compute is None:
            raise G17GUnsupported("G17G compute adapter is unavailable")
        context_id, context = self._execution_context(context_id)
        queue_id = int(queue_id)
        queue = self._compute_queues.get(queue_id)
        if queue is None:
            if queue_id in self._destroyed_compute_queues:
                raise G17GUnsupported("destroyed G17G compute queue")
            raise G17GUnsupported("unknown G17G compute queue")
        self._assert_queue_usable(queue, "compute", queue_id)
        graph = self._retarget_submission_priority(
            self._compute_graph_builder(values_a, values_b),
            queue["firmware_priority"],
        )
        graph.update({
            "logical_queue_id": queue_id,
            "logical_queue_sequence": int(queue["submission_count"]),
            "logical_global_sequence": self._compute_submission_count,
            "logical_context_id": context_id,
            "logical_context_sequence": int(
                context["compute_submission_count"]
            ),
            "firmware_context_id": 1,
            "firmware_transport": "shared-compute",
            "priority": int(queue["priority"]),
            "firmware_priority": int(queue["firmware_priority"]),
        })
        result = self._submit_compute(graph)
        self._validate_compute_result(result)
        queue["submission_count"] += 1
        context["compute_submission_count"] += 1
        self._compute_submission_count += 1
        self.compute_submissions.append({
            "logical_queue_id": queue_id,
            "logical_queue_sequence": graph["logical_queue_sequence"],
            "logical_global_sequence": graph["logical_global_sequence"],
            "logical_context_id": context_id,
            "logical_context_sequence": graph["logical_context_sequence"],
            "execution_claim": result.get("execution_claim"),
        })
        self.last_compute = result
        return result

    @staticmethod
    def _validate_compute_result(result):
        if result.get("captured_input") is not None:
            raise RuntimeError("G17G backend accepted captured input")
        if result.get("execution_claim") != "compute":
            raise RuntimeError("G17G backend lacks a compute execution proof")
        if not result.get("changed"):
            raise RuntimeError("G17G compute did not change its output page")
        if not result.get("exact_first_64_floats"):
            raise RuntimeError("G17G compute output does not match A+B")

    def _completed_fence(self, engine, result, queue_id, context_id):
        """Name one already-measured runtime completion for UAPI sync.

        Runtime adapters are synchronous today.  Compute has one retirement
        boundary; render has independent TA and fragment boundaries and is
        exposed only after both have retired and the semantic output is exact.
        """
        engine = str(engine)
        if engine not in ("compute", "render"):
            raise ValueError("unknown G17G fence engine")
        completion_id = self._completion_sequence
        self._completion_sequence += 1
        metadata = {
            "completion_id": completion_id,
            "engine": engine,
            "logical_queue_id": int(queue_id),
            "logical_context_id": int(context_id),
            "firmware_context_id": 1,
            "completion_source": (
                "exact-output-plus-compute-retirement"
                if engine == "compute" else
                "exact-output-plus-ta-and-fragment-retirement"
            ),
            "captured_input": result.get("captured_input"),
            "execution_claim": result.get("execution_claim"),
            "output_sha256": result.get("after_sha256"),
        }
        command_names = (
            ("compute",) if engine == "compute" else ("ta", "fragment")
        )
        commands = tuple(
            g17g_sync.G17GSoftwareFence(
                signaled=True,
                metadata={"engine": name, "completion_id": completion_id},
            )
            for name in command_names
        )
        fence = self.fence_tracker.track(
            commands,
            name="G17G %s completion %d" % (engine, completion_id),
            metadata=metadata,
        )
        self.submission_fences.append(fence)
        self.last_fence = fence
        return fence

    def _record_published_fault(
        self, engine, queue_id, context_id, fault
    ):
        """Account one firmware-owned command at its attributed owner."""
        engine = str(engine)
        queue_id = int(queue_id)
        context_id, context = self._execution_context(context_id)
        queues = (
            self._compute_queues if engine == "compute"
            else self._render_queues if engine == "render" else None
        )
        submissions = (
            self.compute_submissions if engine == "compute"
            else self.render_submissions if engine == "render" else None
        )
        if queues is None:
            raise ValueError("unknown G17G fault engine")
        queue = queues.get(queue_id)
        if queue is None:
            raise G17GUnsupported(
                "unknown G17G %s queue" % engine
            )
        global_sequence = (
            self._compute_submission_count
            if engine == "compute" else self._render_submission_count
        )
        context_key = "%s_submission_count" % engine
        record = {
            "engine": engine,
            "logical_queue_id": queue_id,
            "logical_queue_sequence": int(queue["submission_count"]),
            "logical_global_sequence": int(global_sequence),
            "logical_context_id": context_id,
            "logical_context_sequence": int(context[context_key]),
            "firmware_context_id": 1,
            **fault.snapshot(),
        }
        queue["submission_count"] += 1
        context[context_key] += 1
        if engine == "compute":
            self._compute_submission_count += 1
        else:
            self._render_submission_count += 1
        submissions.append({
            **record,
            "execution_claim": "failed",
        })
        self.faults.append(record)
        self.last_fault = record
        if fault.fatal:
            self._device_lost = record
            self.fence_tracker.fail_all(
                g17g_sync.G17GWorkError.DEVICE_LOST,
                reason="device-lost",
            )
        elif not fault.recoverable:
            queue["terminal_fault"] = record
        return record

    def _failed_fence(self, engine, record):
        completion_id = self._completion_sequence
        self._completion_sequence += 1
        metadata = {
            "completion_id": completion_id,
            "completion_source": "runtime-published-fault",
            **record,
        }
        command_names = (
            ("compute",) if engine == "compute" else ("ta", "fragment")
        )
        commands = tuple(
            g17g_sync.G17GSoftwareFence(
                metadata={"engine": name, "completion_id": completion_id}
            )
            for name in command_names
        )
        fence = self.fence_tracker.track(
            commands,
            name="G17G %s failure %d" % (engine, completion_id),
            metadata=metadata,
        )
        if not fence.fail(record["error"], reason=record["kind"]):
            raise RuntimeError("fresh G17G failure fence was already terminal")
        self.submission_fences.append(fence)
        self.last_fence = fence
        return fence

    def _submit_synced(self, callback, engine, queue_id, context_id,
                       in_syncs=(), out_syncs=()):
        """Serialize one validated submission through input/output syncs."""
        holder = {}
        sync_plan = g17g_sync.G17GSubmissionSyncPlan(
            in_syncs=in_syncs, out_syncs=out_syncs
        )

        def publish():
            result = callback()
            holder["result"] = result
            return self._completed_fence(
                engine, result, queue_id=queue_id, context_id=context_id
            )

        try:
            fence = sync_plan.publish(publish)
        except g17g_sync.G17GPublishedFault as fault:
            record = self._record_published_fault(
                engine, queue_id, context_id, fault
            )
            fence = self._failed_fence(engine, record)
            sync_plan.bind_terminal(fence)
            result = {
                "captured_input": None,
                "execution_claim": "failed",
                # A failed render can already have spilled partial output.
                # Error status does not prove that its BOs stayed unchanged.
                "changed": fault.metadata.get("output_changed"),
                "fault": record,
            }
            return result, fence
        return holder["result"], fence

    def submit_add_synced(
        self, values_a=None, values_b=None, queue_id=0, context_id=0,
        in_syncs=(), out_syncs=(),
    ):
        """Submit compute after its dependencies and publish its out-fence."""
        return self._submit_synced(
            lambda: self.submit_add(
                values_a, values_b, queue_id=queue_id,
                context_id=context_id,
            ),
            "compute", queue_id, context_id,
            in_syncs=in_syncs, out_syncs=out_syncs,
        )

    def submit_clear_synced(
        self, params=None, token=g17g_backend.RENDER_DEFAULT_TOKEN,
        queue_id=0, context_id=0, in_syncs=(), out_syncs=(),
    ):
        """Submit a clear after its dependencies and publish a pair fence."""
        return self._submit_synced(
            lambda: self.submit_clear(
                params, token, queue_id=queue_id, context_id=context_id
            ),
            "render", queue_id, context_id,
            in_syncs=in_syncs, out_syncs=out_syncs,
        )

    def submit_partial_render_synced(
        self, params=None, token=g17g_backend.PARTIAL_RENDER_TOKEN,
        queue_id=0, context_id=0, in_syncs=(), out_syncs=(),
    ):
        """Submit a partial render through binary or timeline barriers."""
        return self._submit_synced(
            lambda: self.submit_partial_render(
                params, token, queue_id=queue_id, context_id=context_id
            ),
            "render", queue_id, context_id,
            in_syncs=in_syncs, out_syncs=out_syncs,
        )

    def submit_add_batch(self, queue_ids, context_ids=None):
        """Submit an ordered compute batch across arbitrary logical queues.

        Logical queues are host ordering domains over the shared firmware
        channel.  The runtime consumes this schedule in one target-side
        lifecycle, including transparent transport recreation after command
        127, and performs one semantic convergence check per firmware batch.
        """
        self._ensure_device_available()
        if self._submit_compute is None:
            raise G17GUnsupported("G17G compute adapter is unavailable")
        queue_ids = tuple(int(queue_id) for queue_id in queue_ids)
        if not queue_ids:
            raise ValueError("G17G compute batch must not be empty")
        if len(queue_ids) > g17g_backend.COMPUTE_STREAM_SUBMISSION_LIMIT:
            raise G17GUnsupported(
                "G17G compute batch exceeds the decoded 16-bit lifecycle"
            )
        for queue_id in queue_ids:
            if queue_id not in self._compute_queues:
                if queue_id in self._destroyed_compute_queues:
                    raise G17GUnsupported("destroyed G17G compute queue")
                raise G17GUnsupported("unknown G17G compute queue")
            self._assert_queue_usable(
                self._compute_queues[queue_id], "compute", queue_id
            )
        priorities = {
            int(self._compute_queues[queue_id]["firmware_priority"])
            for queue_id in queue_ids
        }
        if len(priorities) != 1:
            raise G17GUnsupported(
                "mixed-priority compute queues require separate firmware "
                "publications"
            )
        if context_ids is None:
            context_ids = (0,) * len(queue_ids)
        else:
            context_ids = tuple(int(context_id) for context_id in context_ids)
        if len(context_ids) != len(queue_ids):
            raise ValueError(
                "G17G compute queue/context schedules must have equal length"
            )
        for context_id in context_ids:
            self._execution_context(context_id)

        queue_sequences = {
            queue_id: int(state["submission_count"])
            for queue_id, state in self._compute_queues.items()
        }
        context_sequences = {
            context_id: int(state["compute_submission_count"])
            for context_id, state in self._execution_contexts.items()
        }
        schedule = []
        for offset, (queue_id, context_id) in enumerate(
            zip(queue_ids, context_ids)
        ):
            schedule.append({
                "logical_queue_id": queue_id,
                "logical_queue_sequence": queue_sequences[queue_id],
                "logical_global_sequence": (
                    self._compute_submission_count + offset
                ),
                "logical_context_id": context_id,
                "logical_context_sequence": context_sequences[context_id],
                "firmware_context_id": 1,
            })
            queue_sequences[queue_id] += 1
            context_sequences[context_id] += 1

        firmware_priority = priorities.pop()
        graph = self._retarget_submission_priority(
            self._compute_graph_builder(), firmware_priority
        )
        graph.update({
            "logical_queue_schedule": tuple(schedule),
            "logical_global_sequence": self._compute_submission_count,
            "submission_count": len(schedule),
            "firmware_transport": "shared-compute",
            "priority": int(
                self._compute_queues[queue_ids[0]]["priority"]
            ),
            "firmware_priority": firmware_priority,
        })
        result = self._submit_compute(graph)
        self._validate_compute_result(result)

        batch = result.get("batch")
        records = () if batch is None else (
            tuple(batch) if isinstance(batch, list) else (batch,)
        )
        exact_tail = sum(
            int(record.get("exact_output_count", 0)) for record in records
        )
        if not all(record.get("all_outputs_exact") for record in records):
            raise RuntimeError("G17G compute batch lacks exact output proof")
        if exact_tail != len(schedule) - 1:
            raise RuntimeError(
                "G17G compute batch output count does not match its schedule"
            )

        for item in schedule:
            queue_id = item["logical_queue_id"]
            self._compute_queues[queue_id]["submission_count"] += 1
            context_id = item["logical_context_id"]
            self._execution_contexts[context_id][
                "compute_submission_count"
            ] += 1
            self.compute_submissions.append({
                **item,
                "execution_claim": result.get("execution_claim"),
            })
        self._compute_submission_count += len(schedule)
        self.last_compute = result
        return result

    def submit_clear(
        self, params=None, token=g17g_backend.RENDER_DEFAULT_TOKEN,
        queue_id=0, context_id=0,
    ):
        """Submit the source-built first clear and require exact page output."""
        products = g17g_backend.build_clear_render_products(params, token)
        result, submission = self._submit_render_products(
            products, queue_id, context_id
        )
        if result.get("execution_claim") != "render":
            raise RuntimeError("G17G backend lacks a render execution proof")
        if not result.get("changed"):
            raise RuntimeError("G17G render did not change its target page")
        if not result.get("exact_clear_page"):
            raise RuntimeError("G17G render target does not match the clear")
        self._commit_render_submission(queue_id, submission, result)
        return result

    def submit_partial_render(
        self, params=None, token=g17g_backend.PARTIAL_RENDER_TOKEN,
        queue_id=0, context_id=0,
    ):
        """Submit a partial graph through a host logical queue."""
        products = g17g_backend.build_partial_render_products(params, token)
        result, submission = self._submit_render_products(
            products, queue_id, context_id
        )
        self._validate_partial_result(result)
        self._commit_render_submission(queue_id, submission, result)
        return result

    def submit_partial_render_batch(
        self, queue_ids, params=None,
        token=g17g_backend.PARTIAL_RENDER_TOKEN,
        direct_draws=None, context_ids=None,
    ):
        """Submit an ordered batch drawn from arbitrary logical queues.

        The adapter receives one firmware stream plus a host-only queue
        schedule.  This is the efficient hardware path: every generation is
        published without a host round trip, followed by one final semantic
        output check.
        """
        self._ensure_device_available()
        if self._submit_render is None:
            raise G17GUnsupported("G17G render adapter is unavailable")
        queue_ids = tuple(int(queue_id) for queue_id in queue_ids)
        if not queue_ids:
            raise ValueError("G17G render batch must not be empty")
        for queue_id in queue_ids:
            if queue_id not in self._render_queues:
                if queue_id in self._destroyed_render_queues:
                    raise G17GUnsupported("destroyed G17G render queue")
                raise G17GUnsupported("unknown G17G render queue")
            self._assert_queue_usable(
                self._render_queues[queue_id], "render", queue_id
            )
        priorities = {
            int(self._render_queues[queue_id]["firmware_priority"])
            for queue_id in queue_ids
        }
        if len(priorities) != 1:
            raise G17GUnsupported(
                "mixed-priority render queues require separate firmware "
                "publications"
            )
        if context_ids is None:
            context_ids = (0,) * len(queue_ids)
        else:
            context_ids = tuple(int(context_id) for context_id in context_ids)
        if len(context_ids) != len(queue_ids):
            raise ValueError(
                "G17G render queue/context schedules must have equal length"
            )
        for context_id in context_ids:
            self._execution_context(context_id)

        queue_sequences = {
            queue_id: int(state["submission_count"])
            for queue_id, state in self._render_queues.items()
        }
        context_sequences = {
            context_id: int(state["render_submission_count"])
            for context_id, state in self._execution_contexts.items()
        }
        schedule = []
        for offset, (queue_id, context_id) in enumerate(
            zip(queue_ids, context_ids)
        ):
            schedule.append({
                "logical_queue_id": queue_id,
                "logical_queue_sequence": queue_sequences[queue_id],
                "logical_global_sequence": (
                    self._render_submission_count + offset
                ),
                "logical_context_id": context_id,
                "logical_context_sequence": context_sequences[context_id],
                "firmware_context_id": 1,
            })
            queue_sequences[queue_id] += 1
            context_sequences[context_id] += 1

        products = g17g_backend.build_partial_render_products(
            params, token, submission_count=len(schedule),
            direct_draws=direct_draws,
        )
        firmware_priority = priorities.pop()
        submission = self._retarget_submission_priority(
            products, firmware_priority
        )
        submission.update({
            "logical_queue_schedule": tuple(schedule),
            "firmware_transport": "shared-paired-render",
            "priority": int(
                self._render_queues[queue_ids[0]]["priority"]
            ),
            "firmware_priority": firmware_priority,
        })
        result = self._submit_render(submission)
        if result.get("captured_input") is not None:
            raise RuntimeError("G17G render backend accepted captured input")
        self._validate_partial_result(result)

        for item in schedule:
            queue_id = item["logical_queue_id"]
            self._render_queues[queue_id]["submission_count"] += 1
            context_id = item["logical_context_id"]
            self._execution_contexts[context_id][
                "render_submission_count"
            ] += 1
            self.render_submissions.append({
                **item,
                "execution_claim": result.get("execution_claim"),
            })
        self._render_submission_count += len(schedule)
        self.last_render = result
        return result
