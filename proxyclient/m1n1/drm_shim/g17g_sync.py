# SPDX-License-Identifier: GPL-2.0-only
"""Host-visible synchronization for the serialized T8142/G17G backend.

G17G compute and render currently share one correctness-first runtime.  A
runtime adapter returns only after the firmware queues have retired and the
semantic output is visible, so the backend turns that measured boundary into
a completed submission fence.  Binary and timeline sync objects name those
fences; they do not pretend that the firmware exposes a cross-engine semaphore.
"""

import struct
import time
from enum import Enum, IntEnum


class G17GWorkError(IntEnum):
    """Negative errno values exposed by failed Asahi submission fences."""

    OUT_OF_MEMORY = -12  # ENOMEM
    MMU_FAULT = -5       # EIO
    CHANNEL = -5         # EIO
    TIMEOUT = -110       # ETIMEDOUT
    KILLED = -125        # ECANCELED
    DEVICE_LOST = -19    # ENODEV
    UNKNOWN = -61        # ENODATA


class G17GPublishedFault(RuntimeError):
    """A runtime-detected failure after firmware publication.

    Pre-publication validation continues to raise its ordinary exception and
    deliberately creates no output fence.  Raising this type tells the
    synchronous backend that firmware owned the command, so its output syncs
    must receive one terminal error fence with queue/context attribution.

    Shader load/store soft faults are not published errors on T8142: unmapped
    loads return zero and stores are discarded under the advertised UAPI
    feature. They must not be converted into EIO fences by this class.
    """

    def __init__(self, kind, error=G17GWorkError.UNKNOWN, *,
                 recoverable=False, fatal=False, metadata=None):
        self.kind = str(kind)
        self.error = int(error)
        if self.error >= 0:
            raise ValueError("published fault errors must be negative errno")
        self.recoverable = bool(recoverable)
        self.fatal = bool(fatal)
        if self.fatal and self.recoverable:
            raise ValueError("a fatal G17G fault cannot be recoverable")
        self.metadata = dict(metadata or {})
        super().__init__(
            "published G17G %s fault (%d)" % (self.kind, self.error)
        )

    def snapshot(self):
        return {
            "kind": self.kind,
            "error": self.error,
            "recoverable": self.recoverable,
            "fatal": self.fatal,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def command_fetch_mmu(cls, **metadata):
        """Build the fatal command-fetch fault proven on T8142.

        The public queue cursors retire, but the SGX fault latch remains set
        and channel 8 consumes neither a fresh queue nor the established
        standalone queue-create transition.  Until a complete GPU reset path
        exists, every pending fence must therefore terminate as device-lost.
        """
        return cls(
            "command-fetch-uat",
            G17GWorkError.DEVICE_LOST,
            fatal=True,
            metadata=metadata,
        )

    @classmethod
    def unclassified_render_failure(cls, **metadata):
        """Fail a published job without inventing OOM from a scalar report.

        An old operand-table starvation experiment produced record type four
        and truncated output, but did not establish an ENOMEM protocol. Keep
        the actual report and output evidence and quarantine the attributed
        queue; neither recovery nor a device-wide failure is established.
        """
        return cls(
            "unclassified-render-report",
            G17GWorkError.UNKNOWN,
            metadata=metadata,
        )

    @classmethod
    def memory_limit_terminated(cls, report, followup, terminal, *, queue_dva,
                                pool_dva, fragment_dva, event_slot, event_value):
        """Classify only the completed, owned native type7/type9 limit path.

        The runtime must actually finish the exchange before raising this;
        a negative growth ACK or scalar type seven alone is insufficient.
        The all-source M5 case continues on the same queues afterward. A
        failed job may already have written its output, so no preservation
        or successful-execution claim is made here.
        """
        from .g17g_growth import build_growth_limit_followup
        expected = build_growth_limit_followup(report, queue_dva=queue_dva,
            pool_dva=pool_dva, fragment_dva=fragment_dva,
            event_slot=event_slot, event_value=event_value)
        if (bytes(followup) != expected or
                bytes(terminal) != struct.pack("<4I", 1, 3, 0, 0) + bytes(56)):
            raise ValueError("memory-limit fault lacks the qualified termination exchange")
        return cls("tvb-memory-limit", G17GWorkError.OUT_OF_MEMORY,
            recoverable=True, metadata=dict(queue_dva=queue_dva, pool_dva=pool_dva,
                fragment_dva=fragment_dva, event_slot=event_slot, event_value=event_value,
                report_hex=bytes(report).hex(), followup_hex=bytes(followup).hex(),
                terminal_hex=bytes(terminal).hex(), output_contents="unspecified after failure"))


class G17GWorkState(str, Enum):
    """Caller-visible state of one published submission."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class G17GRejectedWork:
    """Synchronous pre-publication failure, which has no output fence."""

    def __init__(self, error, stage, metadata=None):
        self.error = error
        self.stage = str(stage)
        self.metadata = dict(metadata or {})

    def snapshot(self):
        return {
            "state": G17GWorkState.REJECTED.value,
            "error": str(self.error),
            "error_type": type(self.error).__name__,
            "stage": self.stage,
            "metadata": dict(self.metadata),
            "fence": None,
        }


class G17GSoftwareFence:
    """One explicit or already-observed completion point."""

    def __init__(self, signaled=False, error=None, metadata=None):
        self._signaled = bool(signaled)
        self.error = error
        self.metadata = dict(metadata or {})

    def signal(self, error=None):
        self.error = error
        self._signaled = True

    def signaled(self):
        return self._signaled

    def snapshot(self):
        return {
            "signaled": self.signaled(),
            "error": self.error,
            "metadata": dict(self.metadata),
        }

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        deadline = time.monotonic() + float(timeout)
        while not self.signaled():
            if time.monotonic() >= deadline:
                raise TimeoutError("G17G software fence did not signal")
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        return self


class G17GSubmissionFence:
    """One submission fence backed by all required engine completions.

    Compute contributes one completion.  Render contributes independent TA
    and fragment completions, and therefore does not signal until both do.
    """

    def __init__(self, fences, name=None, metadata=None):
        self.fences = tuple(fences)
        if not self.fences:
            raise ValueError("a G17G submission fence needs a completion")
        self.name = str(name or "G17G submission")
        self.metadata = dict(metadata or {})
        self._terminal = False
        self._terminal_error = None
        self._terminal_reason = None

    @property
    def error(self):
        if self._terminal:
            return self._terminal_error
        return next(
            (
                fence.error for fence in self._completion_leaves()
                if getattr(fence, "error", None) is not None
            ),
            None,
        )

    @property
    def state(self):
        if not self.signaled():
            return G17GWorkState.PENDING
        return (
            G17GWorkState.COMPLETED
            if self.error is None else G17GWorkState.FAILED
        )

    def signaled(self):
        return self._terminal or all(
            fence.signaled() for fence in self._completion_leaves()
        )

    def _completion_leaves(self):
        """Traverse nested timeline dependencies without Python recursion.

        Terminal aggregates replace their pending children. Preserve child
        order so the first reported error has the same attribution as before.
        """
        pending = list(reversed(self.fences))
        while pending:
            fence = pending.pop()
            if isinstance(fence, G17GSubmissionFence) and not fence._terminal:
                pending.extend(reversed(fence.fences))
            else:
                yield fence

    @property
    def terminal_reason(self):
        return self._terminal_reason

    def fail(self, error, reason="error"):
        """Signal still-pending work with one negative errno-style error."""
        error = int(error)
        if error >= 0:
            raise ValueError("fence errors must be negative errno values")
        # A device reset must not retroactively fail completed work.
        if self.signaled():
            return False
        self._terminal_error = error
        self._terminal_reason = str(reason)
        self._terminal = True
        return True

    def snapshot(self):
        return {
            "name": self.name,
            "state": self.state.value,
            "signaled": self.signaled(),
            "error": self.error,
            "terminal": self._terminal,
            "terminal_reason": self.terminal_reason,
            "metadata": dict(self.metadata),
            "completions": [fence.snapshot() for fence in self.fences],
        }

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        deadline = time.monotonic() + float(timeout)
        while not self.signaled():
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "%s did not signal (error=%r)" % (self.name, self.error)
                )
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        return self


class G17GFenceTracker:
    """Track published submissions for queue-, context-, or device failure."""

    def __init__(self):
        self._fences = []

    def track(self, fences, name=None, metadata=None):
        fence = G17GSubmissionFence(
            fences, name=name, metadata=metadata
        )
        self._fences.append(fence)
        return fence

    def outstanding(self, **metadata):
        return [
            fence for fence in self._fences
            if not fence.signaled() and all(
                fence.metadata.get(key) == value
                for key, value in metadata.items()
            )
        ]

    def fail_matching(self, error, reason="error", **metadata):
        return sum(
            int(fence.fail(error, reason=reason))
            for fence in self.outstanding(**metadata)
        )

    def fail_all(self, error, reason="device-lost"):
        return self.fail_matching(error, reason=reason)

    def prune(self):
        before = len(self._fences)
        self._fences[:] = [
            fence for fence in self._fences if not fence.signaled()
        ]
        return before - len(self._fences)


class G17GLogicalQueue:
    """UAPI queue-handle lifetime around a backend queue allocation.

    Queue destruction removes the caller-visible handle immediately.  Any
    already-published work retains the backend queue until its terminal fence
    signals, at which point the release callback tears it down.
    """

    def __init__(self, release=None, name=None):
        self.name = str(name or "G17G queue")
        self._release = release
        self._accepting = True
        self._released = False
        self._fences = []

    @property
    def accepting(self):
        return self._accepting

    @property
    def released(self):
        return self._released

    def assert_submit_allowed(self):
        if not self._accepting:
            raise RuntimeError("%s has been destroyed" % self.name)

    def track(self, fence):
        self.assert_submit_allowed()
        if not isinstance(fence, G17GSubmissionFence):
            raise TypeError("queue jobs require a G17GSubmissionFence")
        self._fences.append(fence)
        return fence

    def outstanding(self):
        return [fence for fence in self._fences if not fence.signaled()]

    def destroy(self):
        self._accepting = False
        return self.reap()

    def reap(self):
        self._fences[:] = self.outstanding()
        if self._accepting or self._fences or self._released:
            return False
        if self._release is not None:
            self._release()
        self._released = True
        return True


class G17GSyncPoint:
    """One binary or timeline value and its submission fence."""

    def __init__(self, value, fence):
        self.value = int(value)
        self.fence = fence

    @property
    def error(self):
        return self.fence.error

    def signaled(self):
        return self.fence.signaled()

    def wait(self, **kwargs):
        self.fence.wait(**kwargs)
        return self


class G17GSyncObject:
    """A binary sync object or monotonically valued timeline."""

    def __init__(self, timeline=False):
        self.timeline = bool(timeline)
        self._binary = None
        self._points = {}

    def validate_bind(self, value=0):
        value = int(value)
        if value < 0:
            raise ValueError("G17G sync values must be nonnegative")
        if not self.timeline:
            if value:
                raise ValueError("G17G binary sync objects use value zero")
            return
        if value in self._points:
            raise ValueError("G17G timeline point %d is already bound" % value)

    def bind(self, fence, value=0):
        if not isinstance(fence, (G17GSoftwareFence, G17GSubmissionFence)):
            raise TypeError(
                "G17G sync points require a software or submission fence"
            )
        value = int(value)
        self.validate_bind(value)
        point = G17GSyncPoint(value, fence)
        if self.timeline:
            self._points[value] = point
        else:
            self._binary = point
        return point

    def signal(self, value=0, error=None):
        """Install one externally signaled binary or timeline point."""
        value = int(value)
        if self.timeline and value < self.query():
            raise ValueError(
                "cannot signal G17G timeline backwards from %d to %d"
                % (self.query(), value)
            )
        return self.bind(
            G17GSoftwareFence(signaled=True, error=error), value
        )

    def reset(self):
        if self.timeline:
            self._points.clear()
        else:
            self._binary = None

    def _candidates(self, value):
        value = int(value)
        if not self.timeline:
            if value:
                raise ValueError("G17G binary sync objects use value zero")
            return () if self._binary is None else (self._binary,)
        return tuple(
            self._points[key] for key in sorted(self._points) if key >= value
        )

    def point(self, value=0):
        candidates = self._candidates(value)
        if not candidates:
            return None
        return next(
            (point for point in candidates if point.signaled()),
            candidates[0],
        )

    def signaled(self, value=0):
        return any(point.signaled() for point in self._candidates(value))

    def query(self):
        if not self.timeline:
            return int(self._binary is not None and self._binary.signaled())
        return max(
            (
                value for value, point in self._points.items()
                if point.signaled()
            ),
            default=0,
        )

    def wait(self, value=0, timeout=2.0, event_pump=None,
             poll_interval=0.0001):
        deadline = time.monotonic() + float(timeout)
        while True:
            point = self.point(value)
            if point is not None and point.signaled():
                return point
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "G17G sync point %d did not signal" % int(value)
                )
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)


class G17GSubmissionSyncPlan:
    """Transactional input waits and output-fence publication."""

    def __init__(self, in_syncs=(), out_syncs=()):
        self.in_syncs = tuple(self._binding(item) for item in in_syncs)
        self.out_syncs = tuple(self._binding(item) for item in out_syncs)
        self.fence = None

    @staticmethod
    def _binding(item):
        if len(item) != 2:
            raise ValueError("G17G sync binding must be (object, value)")
        sync, value = item
        if not isinstance(sync, G17GSyncObject):
            raise TypeError("G17G sync binding names the wrong object type")
        return sync, int(value)

    def validate(self):
        for sync, value in self.in_syncs:
            if sync.point(value) is None:
                raise ValueError(
                    "G17G input sync point %d has no fence" % value
                )
        seen = set()
        for sync, value in self.out_syncs:
            key = id(sync), value
            if key in seen:
                raise ValueError("duplicate G17G output sync point")
            seen.add(key)
            sync.validate_bind(value)
        return self

    def publish(self, callback, timeout=2.0, event_pump=None):
        self.validate()
        for sync, value in self.in_syncs:
            point = sync.wait(value, timeout=timeout, event_pump=event_pump)
            if point.error is not None:
                raise OSError(-int(point.error), "G17G input sync failed")
        fence = callback()
        if not isinstance(fence, G17GSubmissionFence):
            raise TypeError("G17G publication did not return a fence")
        for sync, value in self.out_syncs:
            sync.bind(fence, value)
        self.fence = fence
        return fence

    def bind_terminal(self, fence):
        """Bind an error fence after the validated callback took ownership."""
        if self.fence is not None:
            raise RuntimeError("G17G sync plan already published a fence")
        if not isinstance(fence, G17GSubmissionFence):
            raise TypeError("G17G terminal publication needs a fence")
        if not fence.signaled() or fence.error is None:
            raise ValueError("G17G terminal publication needs an error fence")
        for sync, value in self.out_syncs:
            sync.bind(fence, value)
        self.fence = fence
        return fence
