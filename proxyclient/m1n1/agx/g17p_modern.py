# SPDX-License-Identifier: MIT
"""File-private lifecycle model for the modern Asahi UAPI on G17P."""

from dataclasses import dataclass, field, replace

from .g17p_sync import (
    G17PLogicalQueue,
    G17PRejectedWork,
    G17PSoftwareFence,
    G17PSubmissionFence,
    G17PSubmissionSyncPlan,
    G17PSyncObject,
)
from .g17p_uapi import (
    DRM_ASAHI_BIND_OBJECT_OP_BIND,
    DRM_ASAHI_BIND_OBJECT_OP_UNBIND,
    DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_SINGLE_PAGE,
    DRM_ASAHI_BIND_UNBIND,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_COMPUTE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_GEM_VM_PRIVATE,
    DRM_ASAHI_GEM_WRITEBACK,
    DRM_ASAHI_RENDER_DBIAS_IS_INT,
    DRM_ASAHI_RENDER_NO_VERTEX_CLUSTERING,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    DRM_ASAHI_RENDER_VERTEX_SCRATCH,
    DRM_ASAHI_SYNC_SYNCOBJ,
    DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ,
    drm_asahi_gem_bind_op,
    drm_asahi_gem_bind_object,
    parse_command_buffer,
)


PAGE_SIZE = 0x4000
# Match the upstream driver's 39-bit UAT userspace window.  Its last two pages
# are reserved, so vm_end is 2^39 - 2 * PAGE_SIZE.
VM_START = PAGE_SIZE
VM_END = (1 << 39) - 2 * PAGE_SIZE
VM_KERNEL_MIN_SIZE = 0x20000000
USC_EXEC_SIZE = 1 << 32
SAMPLER_SIZE = 8
MAX_SAMPLERS = 1024


@dataclass
class G17PModernBO:
    handle: int
    memfd_offset: int
    size: int
    flags: int
    vm_id: int
    token: object = None
    fences: list = field(default_factory=list)


@dataclass
class G17PModernBinding:
    vm_id: int
    addr: int
    size: int
    bo: G17PModernBO
    bo_offset: int
    flags: int
    token: object = None

    @property
    def end(self):
        return self.addr + self.size


@dataclass
class G17PModernObject:
    object_handle: int
    bo: G17PModernBO
    offset: int
    size: int
    flags: int
    token: object = None


@dataclass
class G17PModernVM:
    vm_id: int
    kernel_start: int
    kernel_end: int
    token: object = None
    bindings: list = field(default_factory=list)


@dataclass
class G17PModernQueue:
    queue_id: int
    vm: G17PModernVM
    priority: int
    usc_exec_base: int
    token: object = None
    lifetime: G17PLogicalQueue = None


@dataclass
class G17PModernFile:
    fd: int
    vms: dict = field(default_factory=dict)
    bos: dict = field(default_factory=dict)
    queues: dict = field(default_factory=dict)
    objects: dict = field(default_factory=dict)
    syncs: dict = field(default_factory=dict)
    sync_types: dict = field(default_factory=dict)
    next_vm_id: int = 1
    next_queue_id: int = 1
    next_object_id: int = 1


@dataclass(frozen=True)
class G17PComputeHardwareState:
    """Validated addresses and scalar state for one compute publication."""

    cdm_base: int
    cdm_end: int
    cdm_terminator: int
    sampler_heap: int
    sampler_count: int
    helper_binary: int
    helper_cfg: int
    helper_data: int
    helper_address: int
    usc_exec_base: int
    attachments: tuple
    bindings: tuple


@dataclass(frozen=True)
class G17PRenderHardwareState:
    """Validated addresses and scalar state for one render publication."""

    flags: int
    vdm_base: int
    scissor_base: int
    dbias_base: int
    oclqry_base: int
    depth_base: int
    depth_comp_base: int
    depth_stride: int
    depth_comp_stride: int
    stencil_base: int
    stencil_comp_base: int
    stencil_stride: int
    stencil_comp_stride: int
    zls_ctrl: int
    multisample_control: int
    ppp_control: int
    width: int
    height: int
    layers: int
    utile_width: int
    utile_height: int
    samples: int
    sample_size: int
    utile_config: int
    blocks_per_utile: int
    tile_config: int
    merge_upper_x: int
    merge_upper_y: int
    sampler_heap: int
    sampler_count: int
    vertex_helper_binary: int
    vertex_helper_cfg: int
    vertex_helper_data: int
    fragment_helper_binary: int
    fragment_helper_cfg: int
    fragment_helper_data: int
    bg_usc: int
    bg_rsrc_spec: int
    eot_usc: int
    eot_rsrc_spec: int
    partial_bg_usc: int
    partial_bg_rsrc_spec: int
    partial_eot_usc: int
    partial_eot_rsrc_spec: int
    bgobjdepth: int
    bgobjvals: int
    usc_exec_base: int
    vertex_attachments: tuple
    fragment_attachments: tuple
    bindings: tuple


class G17PModernDriver:
    """Validate modern UAPI ownership and call a hardware adapter.

    The adapter may implement ``create_vm``, ``destroy_vm``, ``create_bo``,
    ``destroy_bo``, ``bind``, ``unbind``, ``create_queue``, ``destroy_queue``
    and ``submit``.  This separation keeps Linux handle semantics testable
    without importing or touching the hardware proxy.
    """

    def __init__(self, adapter):
        self.adapter = adapter
        self.files = {}
        self.deferred_bos = []
        self.deferred_queues = []
        self.rejections = []

    def _record_rejection(self, file, queue, error, stage, command=None,
                          queue_id=None):
        """Retain ownership for a synchronous failure that creates no fence."""
        metadata = {
            "fd": int(file.fd),
            "vm_id": None if queue is None else int(queue.vm.vm_id),
            "context_id": (None if queue is None
                           else queue.vm.token),
            "queue_id": (int(queue_id) if queue is None
                         else int(queue.queue_id)),
            "command_index": (None if command is None
                              else int(command.index)),
            "command_type": (None if command is None
                             else int(command.header.cmd_type)),
        }
        record = G17PRejectedWork(error, stage, metadata)
        self.rejections.append(record)
        return record

    def reap_deferred(self):
        """Release physically dead resources whose terminal fences retired."""
        for queue in tuple(self.deferred_queues):
            queue.lifetime.reap()
            if queue.lifetime.released:
                self.deferred_queues.remove(queue)
        for record in tuple(self.deferred_bos):
            bo = record["bo"]
            bo.fences[:] = [fence for fence in bo.fences
                            if not fence.signaled()]
            if bo.fences:
                continue
            record["release"]()
            self.deferred_bos.remove(record)

    def file(self, fd):
        fd = int(fd)
        return self.files.setdefault(fd, G17PModernFile(fd))

    @staticmethod
    def _call(adapter, name, *args):
        callback = getattr(adapter, name, None)
        return callback(*args) if callback is not None else None

    @staticmethod
    def _next_id(records, start):
        value = int(start)
        while value in records:
            value += 1
        return value

    def create_vm(self, fd, kernel_start, kernel_end):
        file = self.file(fd)
        kernel_start = int(kernel_start)
        kernel_end = int(kernel_end)
        if (kernel_start | kernel_end) & (PAGE_SIZE - 1):
            raise ValueError("VM kernel range must be page aligned")
        if (kernel_start < VM_START or kernel_end > VM_END or
                kernel_end - kernel_start < VM_KERNEL_MIN_SIZE):
            raise ValueError("VM kernel range is outside the advertised range")
        vm_id = self._next_id(file.vms, file.next_vm_id)
        vm = G17PModernVM(vm_id, kernel_start, kernel_end)
        vm.token = self._call(self.adapter, "create_vm", file, vm)
        file.vms[vm_id] = vm
        file.next_vm_id = vm_id + 1
        return vm

    def destroy_vm(self, fd, vm_id):
        self.reap_deferred()
        file = self.file(fd)
        vm = file.vms.get(int(vm_id))
        if vm is None:
            raise KeyError("VM %d does not exist" % int(vm_id))
        if any(queue.vm is vm for queue in file.queues.values()):
            raise RuntimeError("VM %d still owns queues" % vm.vm_id)
        if vm.bindings:
            raise RuntimeError("VM %d still owns bindings" % vm.vm_id)
        if any(queue.vm is vm and not queue.lifetime.released
               for queue in self.deferred_queues):
            raise RuntimeError("VM %d still owns deferred queues" % vm.vm_id)
        if any(any(binding.vm_id == vm.vm_id
                   for binding in record["bindings"])
               for record in self.deferred_bos):
            raise RuntimeError("VM %d still owns deferred BO mappings" % vm.vm_id)
        self._call(self.adapter, "destroy_vm", file, vm)
        del file.vms[vm.vm_id]

    def create_bo(self, fd, handle, memfd_offset, size, flags=0, vm_id=0):
        file = self.file(fd)
        handle = int(handle)
        size = int(size)
        if handle <= 0 or handle in file.bos:
            raise ValueError("invalid or duplicate GEM handle %d" % handle)
        flags = int(flags)
        vm_id = int(vm_id)
        if size <= 0:
            raise ValueError("GEM size must be positive")
        if flags & ~(DRM_ASAHI_GEM_WRITEBACK | DRM_ASAHI_GEM_VM_PRIVATE):
            raise ValueError("unknown GEM create flags")
        if flags & DRM_ASAHI_GEM_VM_PRIVATE:
            if vm_id not in file.vms:
                raise KeyError("private GEM VM %d does not exist" % vm_id)
        elif vm_id:
            raise ValueError("non-private GEM has a VM ID")
        bo = G17PModernBO(
            handle, int(memfd_offset), size, flags, vm_id)
        bo.token = self._call(self.adapter, "create_bo", file, bo)
        file.bos[handle] = bo
        return bo

    def destroy_bo(self, fd, handle):
        self.reap_deferred()
        file = self.file(fd)
        bo = file.bos.get(int(handle))
        if bo is None:
            return False
        # GEM close removes handle and mapping visibility immediately.  The
        # physical adapter teardown remains deferred while any published fence
        # can still reach the BO through one of those mappings.
        bindings = []
        for vm in file.vms.values():
            for binding in tuple(vm.bindings):
                if binding.bo is bo:
                    bindings.append((vm, binding))
                    vm.bindings.remove(binding)
        objects = []
        for obj in tuple(file.objects.values()):
            if obj.bo is bo:
                objects.append(obj)
                del file.objects[obj.object_handle]
        del file.bos[bo.handle]

        def release():
            for vm, binding in bindings:
                self._call(self.adapter, "unbind", file, vm, binding)
            for obj in objects:
                self._call(self.adapter, "unbind_object", file, obj)
            self._call(self.adapter, "destroy_bo", file, bo)

        bo.fences[:] = [fence for fence in bo.fences
                        if not fence.signaled()]
        if bo.fences:
            self.deferred_bos.append({
                "bo": bo,
                "bindings": tuple(binding for _vm, binding in bindings),
                "objects": tuple(objects),
                "release": release,
            })
        else:
            release()
        return True

    @staticmethod
    def _check_user_range(vm, start, end):
        if start < end and start < vm.kernel_end and vm.kernel_start < end:
            raise ValueError("binding overlaps the VM kernel range")

    @staticmethod
    def _overlaps(bindings, start, end):
        return [binding for binding in bindings
                if start < binding.end and binding.addr < end]

    def bind(self, fd, vm_id, operation):
        file = self.file(fd)
        vm = file.vms.get(int(vm_id))
        if vm is None:
            raise KeyError("VM %d does not exist" % int(vm_id))
        if not isinstance(operation, drm_asahi_gem_bind_op):
            raise TypeError("bind operation has the wrong UAPI type")
        start = int(operation.addr)
        size = int(operation.range)
        end = start + size
        if not size or end <= start:
            raise ValueError("binding range is empty or overflows")
        if start < VM_START or end > VM_END:
            raise ValueError("binding range is outside the advertised VM window")
        if (start | size | int(operation.offset)) & (PAGE_SIZE - 1):
            raise ValueError("binding address, range, and offset must be aligned")
        self._check_user_range(vm, start, end)

        if operation.flags & DRM_ASAHI_BIND_UNBIND:
            if (operation.flags != DRM_ASAHI_BIND_UNBIND or operation.handle or
                    operation.offset):
                raise ValueError("unbind has invalid handle, offset, or flags")
            overlaps = tuple(self._overlaps(vm.bindings, start, end))
            replacements = []
            for binding in overlaps:
                self._call(self.adapter, "unbind", file, vm, binding)
                vm.bindings.remove(binding)
                if binding.addr < start:
                    replacements.append(G17PModernBinding(
                        vm.vm_id, binding.addr, start - binding.addr,
                        binding.bo, binding.bo_offset, binding.flags))
                if end < binding.end:
                    delta = end - binding.addr
                    offset = (binding.bo_offset if
                              binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE else
                              binding.bo_offset + delta)
                    replacements.append(G17PModernBinding(
                        vm.vm_id, end, binding.end - end,
                        binding.bo, offset, binding.flags))
            for replacement in replacements:
                replacement.token = self._call(
                    self.adapter, "bind", file, vm, replacement)
                vm.bindings.append(replacement)
            vm.bindings.sort(key=lambda item: item.addr)
            return tuple(overlaps)

        allowed = (DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE |
                   DRM_ASAHI_BIND_SINGLE_PAGE)
        if operation.flags & ~allowed:
            raise ValueError("unknown GEM bind flags")
        if not operation.flags & (DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE):
            raise ValueError("GEM binding needs read or write permission")
        if self._overlaps(vm.bindings, start, end):
            raise ValueError("GEM binding overlaps an existing mapping")
        bo = file.bos.get(int(operation.handle))
        if bo is None:
            raise KeyError("GEM handle %d does not exist" % operation.handle)
        accessed = PAGE_SIZE if operation.flags & DRM_ASAHI_BIND_SINGLE_PAGE else size
        if int(operation.offset) + accessed > bo.size:
            raise ValueError("GEM binding exceeds its object")
        if bo.vm_id and bo.vm_id != vm.vm_id:
            raise ValueError("VM-private GEM belongs to another VM")

        binding = G17PModernBinding(
            vm.vm_id, start, size, bo, int(operation.offset),
            int(operation.flags))
        binding.token = self._call(
            self.adapter, "bind", file, vm, binding)
        vm.bindings.append(binding)
        vm.bindings.sort(key=lambda item: item.addr)
        return binding

    def bind_object(self, fd, operation):
        file = self.file(fd)
        if not isinstance(operation, drm_asahi_gem_bind_object):
            raise TypeError("special bind operation has the wrong UAPI type")
        if operation.vm_id or operation.pad:
            raise ValueError("special bind VM ID and padding must be zero")

        if operation.op == DRM_ASAHI_BIND_OBJECT_OP_UNBIND:
            if (operation.flags or operation.handle or operation.offset or
                    operation.range):
                raise ValueError("special unbind has nonzero bind fields")
            obj = file.objects.pop(int(operation.object_handle), None)
            if obj is None:
                raise KeyError("special object %d does not exist" %
                               int(operation.object_handle))
            self._call(self.adapter, "unbind_object", file, obj)
            return obj

        if operation.op != DRM_ASAHI_BIND_OBJECT_OP_BIND:
            raise ValueError("unknown special bind operation")
        if operation.flags != DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS:
            raise ValueError("unknown special object usage")
        bo = file.bos.get(int(operation.handle))
        if bo is None:
            raise KeyError("GEM handle %d does not exist" % operation.handle)
        offset = int(operation.offset)
        size = int(operation.range)
        if (offset | size) & (PAGE_SIZE - 1):
            raise ValueError("special object range and offset must be aligned")
        if not size or offset + size > bo.size:
            raise ValueError("special object range exceeds its GEM object")
        object_handle = self._next_id(file.objects, file.next_object_id)
        obj = G17PModernObject(
            object_handle, bo, offset, size, int(operation.flags))
        obj.token = self._call(self.adapter, "bind_object", file, obj)
        file.objects[object_handle] = obj
        file.next_object_id = object_handle + 1
        operation.object_handle = object_handle
        return obj

    def create_queue(self, fd, vm_id, priority, usc_exec_base):
        file = self.file(fd)
        vm = file.vms.get(int(vm_id))
        if vm is None:
            raise KeyError("VM %d does not exist" % int(vm_id))
        priority = int(priority)
        if priority not in (0, 1):
            raise ValueError("only low and medium priorities are available")
        usc_exec_base = int(usc_exec_base)
        usc_exec_end = usc_exec_base + USC_EXEC_SIZE
        if usc_exec_base & (USC_EXEC_SIZE - 1):
            raise ValueError("USC execution base must be 4 GiB aligned")
        if (usc_exec_base < VM_START or usc_exec_end <= usc_exec_base or
                usc_exec_end > VM_END):
            raise ValueError(
                "USC execution carveout is outside the VM user range")
        self._check_user_range(vm, usc_exec_base, usc_exec_end)
        queue_id = self._next_id(file.queues, file.next_queue_id)
        queue = G17PModernQueue(
            queue_id, vm, priority, usc_exec_base)
        queue.token = self._call(self.adapter, "create_queue", file, queue)
        queue.lifetime = G17PLogicalQueue(
            release=lambda: self._call(
                self.adapter, "destroy_queue", file, queue),
            name="Asahi queue %d" % queue_id,
        )
        file.queues[queue_id] = queue
        file.next_queue_id = queue_id + 1
        return queue

    def destroy_queue(self, fd, queue_id):
        self.reap_deferred()
        file = self.file(fd)
        queue = file.queues.pop(int(queue_id), None)
        if queue is None:
            raise KeyError("queue %d does not exist" % int(queue_id))
        if not queue.lifetime.destroy():
            self.deferred_queues.append(queue)
        return queue

    def _sync_object(self, file, sync):
        sync_type = int(sync.sync_type)
        if sync_type not in (
                DRM_ASAHI_SYNC_SYNCOBJ,
                DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ):
            raise ValueError("unknown sync object type %d" % sync_type)
        old_type = file.sync_types.setdefault(int(sync.handle), sync_type)
        if old_type != sync_type:
            raise ValueError("sync object type changed")
        return file.syncs.setdefault(
            int(sync.handle),
            G17PSyncObject(timeline=(sync_type ==
                                     DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ)))

    @staticmethod
    def _command_timestamps(command):
        payload = command.payload
        if command.header.cmd_type == DRM_ASAHI_CMD_RENDER:
            return (
                ("vertex_start", payload.ts_vtx.start),
                ("vertex_end", payload.ts_vtx.end),
                ("fragment_start", payload.ts_frag.start),
                ("fragment_end", payload.ts_frag.end),
            )
        if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE:
            return (
                ("compute_start", payload.ts.start),
                ("compute_end", payload.ts.end),
            )
        raise AssertionError("parser returned an unknown hardware command")

    @classmethod
    def _resolve_timestamp_objects(cls, file, command):
        resolved = []
        for name, timestamp in cls._command_timestamps(command):
            handle = int(timestamp.handle)
            if not handle:
                continue
            obj = file.objects.get(handle)
            if obj is None:
                raise KeyError("timestamp object %d does not exist" % handle)
            offset = int(timestamp.offset)
            if offset + 8 > obj.size:
                raise ValueError(
                    "%s timestamp at %#x exceeds object %d size %#x" %
                    (name, offset, handle, obj.size))
            resolved.append((name, obj, offset))
        return replace(command, timestamp_objects=tuple(resolved))

    @staticmethod
    def _bindings_cover(vm, address, size, required, label):
        address = int(address)
        size = int(size)
        end = address + size
        if not size or end <= address:
            raise ValueError("%s range is empty or overflows" % label)
        cursor = address
        covered = []
        for binding in vm.bindings:
            if binding.end <= cursor:
                continue
            if binding.addr > cursor:
                break
            if binding.flags & required != required:
                raise ValueError("%s range has insufficient VM permissions" % label)
            covered.append(binding)
            cursor = min(end, binding.end)
            if cursor == end:
                return tuple(covered)
        raise ValueError("%s range is not completely mapped" % label)

    def _resolve_compute_hardware_state(self, queue, command):
        from .g17p_uapi import DRM_ASAHI_BIND_READ, DRM_ASAHI_BIND_WRITE

        payload = command.payload
        referenced_bindings = []

        def cover(address, size, required, label):
            bindings = self._bindings_cover(
                queue.vm, address, size, required, label)
            referenced_bindings.extend(bindings)
            return bindings

        if int(payload.flags):
            raise ValueError("compute flags must be zero")
        base = int(payload.cdm_ctrl_stream_base)
        end = int(payload.cdm_ctrl_stream_end)
        if (base | end) & 3:
            raise ValueError("compute control-stream bounds must be 4-byte aligned")
        if end <= base:
            raise ValueError("compute control-stream end must follow its base")
        cover(base, end - base, DRM_ASAHI_BIND_READ,
              "compute control stream")

        sampler_heap = int(payload.sampler_heap)
        sampler_count = int(payload.sampler_count)
        if sampler_count > MAX_SAMPLERS:
            raise ValueError("compute sampler count exceeds the UAPI heap limit")
        if bool(sampler_heap) != bool(sampler_count):
            raise ValueError("compute sampler heap and count must both be zero or nonzero")
        if sampler_count:
            if sampler_heap & (SAMPLER_SIZE - 1):
                raise ValueError("compute sampler heap must be 8-byte aligned")
            cover(sampler_heap, sampler_count * SAMPLER_SIZE,
                  DRM_ASAHI_BIND_READ, "compute sampler heap")

        helper_binary = int(payload.helper.binary)
        helper_cfg = int(payload.helper.cfg)
        helper_data = int(payload.helper.data)
        helper_address = 0
        if helper_binary or helper_cfg or helper_data:
            raise ValueError(
                "compute helper programs are unsupported on G17P")

        attachments = []
        for index, attachment in enumerate(command.compute_attachments):
            pointer = int(attachment.pointer)
            size = int(attachment.size)
            cover(pointer, size, DRM_ASAHI_BIND_WRITE,
                  "compute attachment %d" % index)
            attachments.append((pointer, size))

        bindings = []
        seen = set()
        for binding in referenced_bindings:
            if id(binding) in seen:
                continue
            seen.add(id(binding))
            bindings.append(binding)

        return replace(command, hardware_state=G17PComputeHardwareState(
            cdm_base=base,
            cdm_end=end,
            # Native G17P descriptors name the terminating 32-bit word.  The
            # UAPI end is one byte past the first contiguous stream segment.
            cdm_terminator=end - 4,
            sampler_heap=sampler_heap,
            sampler_count=sampler_count,
            helper_binary=helper_binary,
            helper_cfg=helper_cfg,
            helper_data=helper_data,
            helper_address=helper_address,
            usc_exec_base=int(queue.usc_exec_base),
            attachments=tuple(attachments),
            bindings=tuple(bindings),
        ))

    def _resolve_render_hardware_state(self, queue, command):
        payload = command.payload
        referenced_bindings = []

        def cover(address, size, required, label):
            try:
                bindings = self._bindings_cover(
                    queue.vm, address, size, required, label)
            except ValueError:
                callback = (
                    queue.token.get("resolve_internal_range")
                    if isinstance(queue.token, dict) else None
                )
                if callback is None or not callback(
                        int(address), int(size), int(required), label):
                    raise
                bindings = ()
            referenced_bindings.extend(bindings)
            return bindings

        allowed_flags = (
            DRM_ASAHI_RENDER_VERTEX_SCRATCH
            | DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
            | DRM_ASAHI_RENDER_NO_VERTEX_CLUSTERING
            | DRM_ASAHI_RENDER_DBIAS_IS_INT
        )
        flags = int(payload.flags)
        if flags & ~allowed_flags:
            raise ValueError("unknown render flags %#x" % (flags & ~allowed_flags))
        if flags & DRM_ASAHI_RENDER_VERTEX_SCRATCH:
            raise ValueError("vertex scratch helpers are unsupported on G17P")
        if flags & DRM_ASAHI_RENDER_NO_VERTEX_CLUSTERING:
            raise ValueError(
                "single-cluster vertex execution is unsupported on G17P")

        width = int(payload.width_px)
        height = int(payload.height_px)
        layers = int(payload.layers)
        if not 1 <= width <= 16384 or not 1 <= height <= 16384:
            raise ValueError("render dimensions must be within 1..16384")
        if not 1 <= layers <= 2048:
            raise ValueError("render layer count must be within 1..2048")

        utile_width = int(payload.utile_width_px)
        utile_height = int(payload.utile_height_px)
        if (utile_width, utile_height) not in ((32, 32), (32, 16), (16, 16)):
            raise ValueError("render utile dimensions are invalid")
        samples = int(payload.samples)
        try:
            samples_log2 = {1: 0, 2: 1, 4: 2}[samples]
        except KeyError:
            raise ValueError("render sample count must be 1, 2, or 4") from None
        sample_size = int(payload.sample_size_B)
        utile_config = (
            ((utile_width // 16) << 12)
            | ((utile_height // 16) << 14)
            | samples_log2
        )
        utile_bytes = sample_size * utile_width * utile_height * samples
        # The native eight-R32F partial-render workload uses 16 2-KiB TIB
        # blocks: exactly 32 KiB for one 32x32 utile.  That boundary is valid;
        # only configurations larger than the hardware's 16-block allocation
        # are rejected.
        if utile_bytes > 32768:
            raise ValueError("render utile exceeds the 32768-byte tilebuffer limit")
        blocks_per_utile = (utile_bytes + 2047) // 2048
        tile_config = 0x280
        if layers > 1:
            tile_config |= 1
        if flags & DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES:
            tile_config |= 0x10000

        vdm_base = int(payload.vdm_ctrl_stream_base)
        if not vdm_base or vdm_base & 3:
            raise ValueError("render VDM control stream must be nonzero and aligned")
        cover(vdm_base, 4, DRM_ASAHI_BIND_READ, "render VDM control stream")

        def optional_array(address, required, label):
            address = int(address)
            if address:
                if address & 7:
                    raise ValueError("%s must be 8-byte aligned" % label)
                cover(address, 8, required, label)
            return address

        scissor_base = optional_array(
            payload.isp_scissor_base, DRM_ASAHI_BIND_READ,
            "render scissor array")
        if not scissor_base:
            raise ValueError("render scissor array must be nonzero")
        dbias_base = optional_array(
            payload.isp_dbias_base, DRM_ASAHI_BIND_READ,
            "render depth-bias array")
        oclqry_base = optional_array(
            payload.isp_oclqry_base, DRM_ASAHI_BIND_WRITE,
            "render occlusion-query array")

        def zls_buffer(value, label):
            base = int(value.base)
            comp_base = int(value.comp_base)
            stride = int(value.stride)
            comp_stride = int(value.comp_stride)
            if not base and (comp_base or stride or comp_stride):
                raise ValueError("%s ZLS metadata has no base buffer" % label)
            if not comp_base and comp_stride:
                raise ValueError("%s ZLS compression stride has no metadata" % label)
            if layers > 1 and base and not stride:
                raise ValueError("layered %s ZLS buffer needs a stride" % label)
            if stride and (stride & 0x3fff) != 1:
                raise ValueError("%s ZLS stride has invalid packed flags" % label)
            if comp_stride & 0x3fff:
                raise ValueError(
                    "%s ZLS compression stride has invalid packed flags" % label)
            if base:
                # Main strides encode (16 KiB pages - 1) above bit 14 and
                # carry a mandatory low-bit flag. A zero metadata stride is
                # valid: it encodes one 128-byte cache line per layer.
                layer_stride = (((stride >> 14) + 1) * PAGE_SIZE
                                if stride else 0)
                cover(base, layer_stride * (layers - 1) + 1,
                      DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                      "%s ZLS buffer" % label)
            if comp_base:
                comp_layer_stride = ((comp_stride >> 14) + 1) * 0x80
                cover(comp_base, comp_layer_stride * (layers - 1) + 1,
                      DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                      "%s ZLS compression metadata" % label)
            return base, comp_base, stride, comp_stride

        depth = zls_buffer(payload.depth, "depth")
        stencil = zls_buffer(payload.stencil, "stencil")

        sampler_heap = int(payload.sampler_heap)
        sampler_count = int(payload.sampler_count)
        if sampler_count > MAX_SAMPLERS:
            raise ValueError("render sampler count exceeds the UAPI heap limit")
        if bool(sampler_heap) != bool(sampler_count):
            raise ValueError("render sampler heap and count must both be zero or nonzero")
        if sampler_count:
            if sampler_heap & (SAMPLER_SIZE - 1):
                raise ValueError("render sampler heap must be 8-byte aligned")
            cover(sampler_heap, sampler_count * SAMPLER_SIZE,
                  DRM_ASAHI_BIND_READ, "render sampler heap")

        vertex_helper = (
            int(payload.vertex_helper.binary),
            int(payload.vertex_helper.cfg),
            int(payload.vertex_helper.data),
        )
        fragment_helper = (
            int(payload.fragment_helper.binary),
            int(payload.fragment_helper.cfg),
            int(payload.fragment_helper.data),
        )
        if any(vertex_helper) or any(fragment_helper):
            raise ValueError("render helper programs are unsupported on G17P")

        def program(value, label):
            value = int(value)
            if not value:
                raise ValueError("%s program must be nonzero" % label)
            # drm_asahi_bg_eot::usc is a tagged pointer.  Bits 0..2 are
            # configuration rather than part of the userspace allocation.
            address = int(queue.usc_exec_base) + (value & ~7)
            cover(address, 4, DRM_ASAHI_BIND_READ, "%s program" % label)
            return value

        bg_usc = program(payload.bg.usc, "render background")
        eot_usc = program(payload.eot.usc, "render end-of-tile")
        partial_bg_usc = program(
            payload.partial_bg.usc, "render partial background")
        partial_eot_usc = program(
            payload.partial_eot.usc, "render partial end-of-tile")

        def attachments(records, label):
            result = []
            for index, attachment in enumerate(records):
                pointer = int(attachment.pointer)
                size = int(attachment.size)
                cover(pointer, size, DRM_ASAHI_BIND_WRITE,
                      "%s attachment %d" % (label, index))
                result.append((pointer, size))
            return tuple(result)

        vertex_attachments = attachments(
            command.vertex_attachments, "vertex")
        fragment_attachments = attachments(
            command.fragment_attachments, "fragment")

        bindings = []
        seen = set()
        for binding in referenced_bindings:
            if id(binding) in seen:
                continue
            seen.add(id(binding))
            bindings.append(binding)

        return replace(command, hardware_state=G17PRenderHardwareState(
            flags=flags,
            vdm_base=vdm_base,
            scissor_base=scissor_base,
            dbias_base=dbias_base,
            oclqry_base=oclqry_base,
            depth_base=depth[0],
            depth_comp_base=depth[1],
            depth_stride=depth[2],
            depth_comp_stride=depth[3],
            stencil_base=stencil[0],
            stencil_comp_base=stencil[1],
            stencil_stride=stencil[2],
            stencil_comp_stride=stencil[3],
            zls_ctrl=int(payload.zls_ctrl),
            multisample_control=int(payload.ppp_multisamplectl),
            ppp_control=int(payload.ppp_ctrl),
            width=width,
            height=height,
            layers=layers,
            utile_width=utile_width,
            utile_height=utile_height,
            samples=samples,
            sample_size=sample_size,
            utile_config=utile_config,
            blocks_per_utile=blocks_per_utile,
            tile_config=tile_config,
            merge_upper_x=int(payload.isp_merge_upper_x),
            merge_upper_y=int(payload.isp_merge_upper_y),
            sampler_heap=sampler_heap,
            sampler_count=sampler_count,
            vertex_helper_binary=vertex_helper[0],
            vertex_helper_cfg=vertex_helper[1],
            vertex_helper_data=vertex_helper[2],
            fragment_helper_binary=fragment_helper[0],
            fragment_helper_cfg=fragment_helper[1],
            fragment_helper_data=fragment_helper[2],
            bg_usc=bg_usc,
            bg_rsrc_spec=int(payload.bg.rsrc_spec),
            eot_usc=eot_usc,
            eot_rsrc_spec=int(payload.eot.rsrc_spec),
            partial_bg_usc=partial_bg_usc,
            partial_bg_rsrc_spec=int(payload.partial_bg.rsrc_spec),
            partial_eot_usc=partial_eot_usc,
            partial_eot_rsrc_spec=int(payload.partial_eot.rsrc_spec),
            bgobjdepth=int(payload.isp_bgobjdepth),
            bgobjvals=int(payload.isp_bgobjvals),
            usc_exec_base=int(queue.usc_exec_base),
            vertex_attachments=vertex_attachments,
            fragment_attachments=fragment_attachments,
            bindings=tuple(bindings),
        ))

    def signal_external_sync(self, fd, sync, error=None):
        file = self.file(fd)
        obj = self._sync_object(file, sync)
        return obj.signal(int(sync.timeline_value), error=error)

    def submit(self, fd, queue_id, command_buffer, in_syncs=(), out_syncs=()):
        file = self.file(fd)
        queue = file.queues.get(int(queue_id))
        if queue is None:
            error = KeyError("queue %d does not exist" % int(queue_id))
            self._record_rejection(
                file, None, error, "queue-lookup", queue_id=queue_id)
            raise error
        try:
            queue.lifetime.assert_submit_allowed()
        except Exception as error:
            self._record_rejection(file, queue, error, "queue-lifetime")
            raise
        try:
            parsed = tuple(parse_command_buffer(command_buffer))
        except Exception as error:
            self._record_rejection(file, queue, error, "command-buffer")
            raise
        resolved = []
        for command in parsed:
            try:
                command = self._resolve_timestamp_objects(file, command)
                command = (
                    self._resolve_compute_hardware_state(queue, command)
                    if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE else
                    self._resolve_render_hardware_state(queue, command))
            except Exception as error:
                self._record_rejection(
                    file, queue, error, "command-validation", command)
                raise
            resolved.append(command)
        commands = tuple(resolved)
        try:
            self._call(self.adapter, "preflight", file, queue, commands)
        except Exception as error:
            self._record_rejection(file, queue, error, "adapter-preflight")
            raise

        in_bindings = []
        for sync in in_syncs:
            obj = self._sync_object(file, sync)
            value = int(sync.timeline_value)
            if obj.point(value) is None:
                # The drm-shim's generic syncobj layer owns external signaling.
                # A synchronous adapter reaches this point only after it allowed
                # the ioctl to run, so represent that imported dependency as done.
                obj.bind(G17PSoftwareFence(signaled=True), value)
            in_bindings.append((obj, value))
        out_bindings = [
            (self._sync_object(file, sync), int(sync.timeline_value))
            for sync in out_syncs
        ]
        plan = G17PSubmissionSyncPlan(in_bindings, out_bindings)

        def publish():
            fence = self._call(
                self.adapter, "submit", file, queue, commands)
            if not isinstance(fence, G17PSubmissionFence):
                raise TypeError("modern hardware adapter returned no submission fence")
            return fence

        publication_called = []

        def attributed_publish():
            publication_called.append(True)
            return publish()

        try:
            fence = plan.publish(attributed_publish)
        except Exception as error:
            if not publication_called:
                self._record_rejection(
                    file, queue, error, "synchronization")
            raise
        attribution = {
            "fd": int(file.fd),
            "vm_id": int(queue.vm.vm_id),
            "context_id": queue.vm.token,
            "queue_id": int(queue.queue_id),
            "command_indices": tuple(
                int(command.index) for command in commands),
            "command_types": tuple(
                int(command.header.cmd_type) for command in commands),
        }
        fence.metadata.update(attribution)
        if len(fence.fences) == len(commands):
            for child, command in zip(fence.fences, commands):
                child_metadata = getattr(child, "metadata", None)
                if child_metadata is not None:
                    child_metadata.update(attribution)
                    child_metadata.update(
                        command_index=int(command.index),
                        command_type=int(command.header.cmd_type),
                    )
        resources = []
        seen = set()
        for command in commands:
            for _name, obj, _offset in command.timestamp_objects:
                if id(obj) not in seen:
                    seen.add(id(obj))
                    resources.append(obj)
        fence.resources = tuple(resources)
        bindings = []
        seen = set()
        for command in commands:
            state = command.hardware_state
            if state is None:
                continue
            for binding in state.bindings:
                if id(binding) in seen:
                    continue
                seen.add(id(binding))
                bindings.append(binding)
        fence.bindings = tuple(bindings)
        bos = []
        seen = set()
        for binding in bindings:
            if id(binding.bo) in seen:
                continue
            seen.add(id(binding.bo))
            bos.append(binding.bo)
        fence.bos = tuple(bos)
        for bo in bos:
            bo.fences.append(fence)
        for obj in resources:
            if fence not in obj.bo.fences:
                obj.bo.fences.append(fence)
        queue.lifetime.track(fence)
        queue.lifetime.reap()
        self.reap_deferred()
        return fence, commands
