# SPDX-License-Identifier: MIT
"""Host synchronization objects for G17P queue fences."""

import time
from enum import Enum, IntEnum


class G17PWorkError(IntEnum):
    """Linux errno values exposed by failed Asahi submission fences."""

    MMU_FAULT = -5       # EIO
    CHANNEL = -5         # EIO
    TIMEOUT = -110       # ETIMEDOUT
    KILLED = -125        # ECANCELED
    DEVICE_LOST = -19    # ENODEV
    UNKNOWN = -61        # ENODATA


class G17PWorkState(str, Enum):
    """UAPI-visible terminal classification for one submission fence."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class G17PRejectedWork:
    """Synchronous pre-publication failure, which deliberately has no fence."""

    def __init__(self, error, stage, metadata=None):
        self.error = error
        self.stage = str(stage)
        self.metadata = dict(metadata or {})

    def snapshot(self):
        return {
            "state": G17PWorkState.REJECTED.value,
            "error": str(self.error),
            "error_type": type(self.error).__name__,
            "stage": self.stage,
            "metadata": dict(self.metadata),
            "fence": None,
        }


class G17PSoftwareFence:
    """A host-signaled fence used for explicit signals and error points."""

    def __init__(self, signaled=False, error=None):
        self._signaled = bool(signaled)
        self.error = error

    def signal(self, error=None):
        self.error = error
        self._signaled = True

    def signaled(self):
        return self._signaled

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        deadline = time.monotonic() + timeout
        while True:
            if self.signaled():
                return self
            if time.monotonic() >= deadline:
                break
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        raise TimeoutError("software fence did not signal")


class G17PSubmissionFence:
    """One UAPI submission fence backed by all of its firmware queues.

    A render command has separate TA and fragment queue completion points,
    while a compute command has one CL2 point.  Userspace sees one fence for
    the complete submission, so no constituent queue may signal it alone.
    Published work may also be terminated by a command or device error even
    when its queue cursor can no longer reach the normal completion point.
    """

    def __init__(self, fences, name=None, metadata=None):
        self.fences = tuple(fences)
        if not self.fences:
            raise ValueError("a submission fence needs at least one command fence")
        self.name = name or "G17P submission"
        self.metadata = dict(metadata or {})
        self._terminal = False
        self._terminal_error = None
        self._terminal_reason = None

    @property
    def error(self):
        if self._terminal:
            return self._terminal_error
        for fence in self.fences:
            error = getattr(fence, "error", None)
            if error is not None:
                return error
        return None

    def signaled(self):
        return self._terminal or all(fence.signaled() for fence in self.fences)

    @property
    def state(self):
        if not self.signaled():
            return G17PWorkState.PENDING
        if self.error is None:
            return G17PWorkState.COMPLETED
        return G17PWorkState.FAILED

    @property
    def terminal_reason(self):
        if self._terminal_reason is not None:
            return self._terminal_reason
        for fence in self.fences:
            reason = getattr(fence, "terminal_reason", None)
            if reason is not None:
                return reason
        return None

    def fail(self, error, reason="error"):
        """Terminate pending work with a negative errno-style error.

        Completed work remains successful.  This mirrors dma-fence behavior:
        an error is attached before signaling, and a later device reset cannot
        retroactively fail an already completed submission.
        """
        error = int(error)
        if error >= 0:
            raise ValueError("fence errors must be negative errno values")
        if self.signaled():
            return False
        self._terminal_error = error
        self._terminal_reason = str(reason)
        self._terminal = True
        return True

    def snapshot(self):
        children = []
        for fence in self.fences:
            snapshot = getattr(fence, "snapshot", None)
            children.append(snapshot() if snapshot is not None else {
                "signaled": bool(fence.signaled()),
                "error": getattr(fence, "error", None),
            })
        return {
            "name": self.name,
            "state": self.state.value,
            "signaled": self.signaled(),
            "error": self.error,
            "terminal": self._terminal,
            "terminal_reason": self.terminal_reason,
            "metadata": dict(self.metadata),
            "commands": children,
        }

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        deadline = time.monotonic() + timeout
        while True:
            if self.signaled():
                return self
            if time.monotonic() >= deadline:
                break
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        raise TimeoutError(
            "%s did not signal: %r" % (self.name, self.snapshot()))


class G17PFenceTracker:
    """Tracks published submissions so fatal teardown can signal all waiters."""

    def __init__(self):
        self._fences = []

    def track(self, fences, name=None, metadata=None):
        fence = G17PSubmissionFence(fences, name=name, metadata=metadata)
        self._fences.append(fence)
        return fence

    def outstanding(self, **metadata):
        return [
            fence for fence in self._fences
            if not fence.signaled() and all(
                fence.metadata.get(key) == value
                for key, value in metadata.items())
        ]

    def fail_all(self, error, reason="device-lost"):
        return self.fail_matching(error, reason=reason)

    def fail_matching(self, error, reason="error", **metadata):
        """Signal pending submissions selected by queue/VM ownership."""
        failed = 0
        for fence in self.outstanding(**metadata):
            failed += int(fence.fail(error, reason=reason))
        return failed

    def prune(self):
        before = len(self._fences)
        self._fences[:] = [fence for fence in self._fences
                           if not fence.signaled()]
        return before - len(self._fences)


class G17PLogicalQueue:
    """UAPI queue-handle lifetime around a firmware queue allocation.

    Destroying a DRM queue removes the userspace handle immediately, but jobs
    already published through it retain the underlying queue until their
    fences signal.  The release callback performs that later physical teardown.
    """

    def __init__(self, release=None, name=None):
        self.name = name or "G17P queue"
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
        if not isinstance(fence, G17PSubmissionFence):
            raise TypeError("queue jobs require a G17PSubmissionFence")
        self._fences.append(fence)
        return fence

    def outstanding(self):
        return [fence for fence in self._fences if not fence.signaled()]

    def destroy(self):
        """Stop new submissions and release once existing work is complete."""
        self._accepting = False
        return self.reap()

    def reap(self):
        """Release a destroyed queue after its final published fence signals."""
        self._fences[:] = self.outstanding()
        if self._accepting or self._fences or self._released:
            return False
        if self._release is not None:
            self._release()
        self._released = True
        return True


class G17PSyncPoint:
    """One binary or timeline point and its backing fence."""

    def __init__(self, value, fence):
        self.value = int(value)
        self.fence = fence

    @property
    def error(self):
        return getattr(self.fence, "error", None)

    def signaled(self):
        return bool(self.fence.signaled())

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        return self.fence.wait(
            timeout=timeout,
            event_pump=event_pump,
            poll_interval=poll_interval,
        )


class G17PSyncObject:
    """Binary or monotonically valued timeline synchronization object.

    Queue fences remain owned by their submissions. Binding them here only
    gives UAPI-visible names to those completion points.
    """

    def __init__(self, timeline=False):
        self.timeline = bool(timeline)
        self._binary = None
        self._points = {}

    def bind(self, fence, value=0):
        value = int(value)
        self.validate_bind(value)
        point = G17PSyncPoint(value, fence)
        if not self.timeline:
            self._binary = point
            return point
        self._points[value] = point
        return point

    def validate_bind(self, value=0):
        """Check an output point without changing the sync object.

        Submit validation must happen before firmware publication.  Keeping
        this check separate lets the UAPI layer reject a bad out-sync without
        replacing the caller's existing binary fence or adding a timeline
        point.
        """
        value = int(value)
        if value < 0:
            raise ValueError("sync point values must be nonnegative")
        if not self.timeline:
            if value:
                raise ValueError("binary sync objects use point zero")
            return
        if value in self._points:
            raise ValueError("timeline point %d is already bound" % value)

    def signal(self, value=0, error=None):
        fence = G17PSoftwareFence(signaled=True, error=error)
        if self.timeline:
            value = int(value)
            if value < self.query():
                raise ValueError(
                    "cannot signal timeline backwards from %d to %d" %
                    (self.query(), value))
        return self.bind(fence, value)

    def reset(self):
        if self.timeline:
            self._points.clear()
        else:
            self._binary = None

    def _candidates(self, value):
        if not self.timeline:
            if int(value):
                raise ValueError("binary sync objects use point zero")
            return [] if self._binary is None else [self._binary]
        value = int(value)
        return [self._points[key] for key in sorted(self._points)
                if key >= value]

    def point(self, value=0):
        candidates = self._candidates(value)
        if not candidates:
            return None
        for point in candidates:
            if point.signaled():
                return point
        return candidates[0]

    def signaled(self, value=0):
        candidates = self._candidates(value)
        return any(point.signaled() for point in candidates)

    def query(self):
        if not self.timeline:
            return int(self._binary is not None and self._binary.signaled())
        signaled = [value for value, point in self._points.items()
                    if point.signaled()]
        return max(signaled, default=0)

    def wait(self, value=0, timeout=2.0, event_pump=None,
             poll_interval=0.0001):
        deadline = time.monotonic() + timeout
        while True:
            candidates = self._candidates(value)
            for point in candidates:
                if point.signaled():
                    return point
            if time.monotonic() >= deadline:
                break
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        raise TimeoutError(
            "sync object point %d did not signal" % int(value))


class G17PSubmissionSyncPlan:
    """Transactional in/out-sync handling for one UAPI submission.

    The real Asahi UAPI resolves input dependencies before scheduling and only
    installs output fences after the complete command buffer has been parsed,
    built, and committed.  A validation or build failure is synchronous and
    must leave all output sync objects untouched.
    """

    def __init__(self, in_syncs=(), out_syncs=()):
        self.in_syncs = tuple(self._binding(item) for item in in_syncs)
        self.out_syncs = tuple(self._binding(item) for item in out_syncs)
        self.fence = None

    @staticmethod
    def _binding(item):
        if len(item) != 2:
            raise ValueError("sync binding must be (sync_object, value)")
        sync, value = item
        if not isinstance(sync, G17PSyncObject):
            raise TypeError("sync binding does not name a G17PSyncObject")
        return sync, int(value)

    def validate(self):
        for sync, value in self.in_syncs:
            if sync.point(value) is None:
                raise ValueError(
                    "input sync point %d has no fence" % value)
        for sync, value in self.out_syncs:
            sync.validate_bind(value)
        return self

    def wait_inputs(self, timeout=2.0, event_pump=None,
                    poll_interval=0.0001):
        for sync, value in self.in_syncs:
            point = sync.wait(
                value,
                timeout=timeout,
                event_pump=event_pump,
                poll_interval=poll_interval,
            )
            if point.error is not None:
                raise OSError(-int(point.error),
                              "input sync point failed")
        return self

    def publish(self, callback, timeout=2.0, event_pump=None,
                poll_interval=0.0001):
        """Run a validated publication and atomically expose its out-fence."""
        self.validate()
        self.wait_inputs(
            timeout=timeout,
            event_pump=event_pump,
            poll_interval=poll_interval,
        )
        fence = callback()
        if not isinstance(fence, G17PSubmissionFence):
            raise TypeError("published submission did not return its fence")
        for sync, value in self.out_syncs:
            sync.bind(fence, value)
        self.fence = fence
        return fence
