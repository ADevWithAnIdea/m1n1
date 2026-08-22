#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import errno, ctypes, sys, atexit, os, os.path, mmap
from construct import *

from m1n1 import malloc
from m1n1.utils import Register32
from m1n1.agx import AGX
from m1n1.agx.g17p_shim import (
    G17P_RENDER_CONTEXT_BASE,
    G17PShimBackend,
    G17PUnsupported,
)
from m1n1.agx.render import *
from m1n1.agx.uapi import *
from m1n1.proxyutils import *
from m1n1.utils import *

PAGE_SIZE = 32768
SHIM_MEM_SIZE = 4 * 1024 * 1024 * 1024

class IOCTL(Register32):
    NR = 7, 0
    TYPE = 15, 8
    SIZE = 29, 16
    DIR = 31, 30

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2

_IO = lambda type, nr: IOCTL(TYPE=type, NR=nr, SIZE=0, DIR=_IOC_NONE)
_IOR = lambda type, nr, size: IOCTL(TYPE=type, NR=nr, SIZE=size, DIR=_IOC_READ)
_IOW = lambda type, nr, size: IOCTL(TYPE=type, NR=nr, SIZE=size, DIR=_IOC_WRITE)
_IOWR = lambda type, nr, size: IOCTL(TYPE=type, NR=nr, SIZE=size, DIR=_IOC_READ|_IOC_WRITE)

DRM_IOCTL_BASE = ord('d')

def IO(nr):
    def dec(f):
        f._ioctl = _IO(DRM_IOCTL_BASE, nr)
        return f
    return dec

def IOR(nr, cls):
    def dec(f):
        f._ioctl = _IOR(DRM_IOCTL_BASE, nr, cls.sizeof())
        f._arg_cls = cls
        return f
    return dec

def IOW(nr, cls):
    def dec(f):
        f._ioctl = _IOW(DRM_IOCTL_BASE, nr, cls.sizeof())
        f._arg_cls = cls
        return f
    return dec

def IOWR(nr, cls):
    def dec(f):
        f._ioctl = _IOWR(DRM_IOCTL_BASE, nr, cls.sizeof())
        f._arg_cls = cls
        return f
    return dec


class _G17PModernHardwareAdapter:
    """Hardware callbacks for the file-private modern UAPI model."""

    TIMESTAMP_APERTURE_BASE = 0xFFFFFC2181400000
    TIMESTAMP_APERTURE_SIZE = 0x04000000
    # Deliberately narrow corpus-backed render used only to prove the C DRM
    # interposer and modern UAPI transport. Mesa's original command is fully
    # resolved before these hardware fields are substituted.
    TRANSPORT_ORACLE = {
        "flags": 1 << 1,
        "encoder_ptr": 0x1000018000,
        "scissor_array": 0x100019A0000,
        "depth_bias_array": 0x10001AF8000,
        "ppp_multisamplectl": 0x88,
        "ppp_ctrl": 0x202,
        "utile_width": 32,
        "utile_height": 32,
        "samples": 1,
        "sample_size": 1,
        "iogpu_unk_49": 1,
        "utile_config": 0xA000,
        "tile_config": 0x10280,
        "load_pipeline": 0x01990240,
        "load_pipeline_bind": 0x40,
        "store_pipeline": 0x01990640,
        "store_pipeline_bind": 0,
        "partial_reload_pipeline": 0x01990240,
        "partial_reload_pipeline_bind": 0x40,
        "partial_store_pipeline": 0x01990640,
        "partial_store_pipeline_bind": 0,
        "usc_exec_base": 0x10000000000,
    }

    def __init__(self, front):
        self.front = front
        self.timestamp_allocations = []
        self.compute_runtime = None
        self.render_since_compute = False
        self.device_lost = False
        self.fatal_notification = None

    def _install_fatal_callback(self):
        """Route an RTKit crash notification into every outstanding fence."""
        front = self.front
        runtime = getattr(front, "g17p_boot_runtime", None) or {}
        ascs = tuple(runtime.get("ascs", ()))
        if not ascs and getattr(front, "g17p_asc", None) is not None:
            ascs = (front.g17p_asc,)

        def fatal_callback(endpoint, msg):
            self.device_lost = True
            self.fatal_notification = {
                "endpoint": int(endpoint.epnum),
                "dva": int(msg.DVA),
                "size": 0x1000 * int(msg.SIZE),
            }
            from .g17p_sync import G17PWorkError
            failed = front.g17p.fail_all_fences(G17PWorkError.DEVICE_LOST)
            print(
                "G17P FATAL: RTKit endpoint %#x crash DVA %#x size %#x; "
                "failed %d outstanding command fence(s)" % (
                    endpoint.epnum, int(msg.DVA),
                    0x1000 * int(msg.SIZE), failed),
                flush=True,
            )

        for asc in ascs:
            asc.g17p_fatal_callback = fatal_callback

    def create_vm(self, file, vm):
        front = self.front
        if (getattr(front, "g17p_deferred_modern", False)
                and not front.initialized):
            owner = (file.fd, vm.vm_id)
            context = front.g17p_modern_vm_contexts.get(owner)
            if context is None:
                context = front.g17p_next_context
                front.g17p_next_context += 1
                front.g17p_modern_vm_contexts[owner] = context
            front.log(
                "modern DRM file %d VM %d deferred as logical context %d" %
                (file.fd, vm.vm_id, context))
            return context
        front.init()
        self._install_fatal_callback()
        owner = (file.fd, vm.vm_id)
        context = front.g17p_modern_vm_contexts.get(owner)
        if context is not None:
            return context
        used = set(front.g17p_fd_contexts.values())
        used.update(front.g17p_modern_vm_contexts.values())
        context = front.g17p.primary_execution_context
        if context in used:
            context = 1
            while context in used:
                context += 1
        if context >= front.g17p.space.uat.NUM_CONTEXTS:
            raise G17PUnsupported("no free G17P hardware context slot")
        front.g17p.create_execution_context(context)
        front.g17p_modern_vm_contexts[owner] = context
        front.log(
            "modern DRM file %d VM %d -> UAT context %d" %
            (file.fd, vm.vm_id, context))
        return context

    def destroy_vm(self, file, vm):
        front = self.front
        context = front.g17p_modern_vm_contexts.pop((file.fd, vm.vm_id))
        if getattr(front, "g17p_source_partial_integration", False):
            # The one-shot integration submit owns the cold opening graph as
            # device state; this logical Mesa VM never installs a second UAT.
            return
        if context == front.g17p.primary_execution_context:
            return
        front.g17p.release_execution_context_render_objects(context)
        front.g17p.destroy_execution_context(context)

    def create_bo(self, _file, bo):
        mapping = mmap.mmap(
            self.front.memfd, bo.size, offset=bo.memfd_offset)
        return {"map": mapping, "pa": None, "alloc_size": bo.size}

    def destroy_bo(self, _file, bo):
        mapping = bo.token.get("map")
        if mapping is not None:
            mapping.close()
            bo.token["map"] = None

    def _reap_timestamp_allocations(self):
        for token in tuple(self.timestamp_allocations):
            fences = [fence for fence in token["fences"]
                      if not fence.signaled()]
            token["fences"] = fences
            if not token["unbound"] or fences:
                continue
            if token["mapped"]:
                self.front.g17p.unmap_firmware_at(
                    token["address"], token["size"])
            self.timestamp_allocations.remove(token)

    def _timestamp_address(self, size):
        self._reap_timestamp_allocations()
        cursor = self.TIMESTAMP_APERTURE_BASE
        for token in sorted(
                self.timestamp_allocations,
                key=lambda allocation: allocation["address"]):
            if cursor + size <= token["address"]:
                return cursor
            cursor = max(cursor, token["address"] + token["size"])
        if cursor + size > self.TIMESTAMP_APERTURE_BASE + self.TIMESTAMP_APERTURE_SIZE:
            raise G17PUnsupported("G17P timestamp aperture is exhausted")
        return cursor

    def bind_object(self, _file, obj):
        front = self.front
        if not (getattr(front, "g17p_deferred_modern", False)
                and not front.initialized):
            front.init()
        address = self._timestamp_address(obj.size)
        token = {
            "bo": obj.bo,
            "offset": obj.offset,
            "size": obj.size,
            "address": address,
            "pa": None,
            "mapped": False,
            "fences": [],
            "unbound": False,
        }
        self.timestamp_allocations.append(token)
        return token

    def unbind_object(self, _file, obj):
        obj.token["unbound"] = True
        self._reap_timestamp_allocations()

    def _bo_pa(self, bo):
        token = bo.token
        if token["pa"] is None:
            page = self.front.g17p.space.uat.PAGE_SIZE
            size = (bo.size + page - 1) & ~(page - 1)
            pa = self.front.g17p.u.memalign(page, size)
            self.front.g17p.u.proxy.memset32(pa, 0, size)
            self.front.g17p.u.proxy.dc_civac(pa, size)
            token["pa"] = pa
            token["alloc_size"] = size
        return token["pa"]

    def bind(self, _file, vm, binding):
        front = self.front
        if (getattr(front, "g17p_deferred_modern", False)
                and not front.initialized):
            return {"space": None, "mapping": None}
        context = int(vm.token)
        state = front.g17p.execution_contexts[context]
        # Binding ownership is accepted now, but the PTE is installed only
        # once the command path is known. Compute uses admitted contexts 2/3;
        # replacing context 1 here would destroy the pending opening render.
        return {"space": state["space"], "mapping": None}

    def unbind(self, _file, _vm, binding):
        mapping = binding.token.get("mapping")
        if mapping is not None:
            binding.token["space"].unmap(mapping)

    @staticmethod
    def _render_dva(address):
        """Translate a userspace low render-context VA to its UAT alias."""
        address = int(address)
        if address < G17P_RENDER_CONTEXT_BASE:
            return G17P_RENDER_CONTEXT_BASE + address
        return address

    def _ensure_render_vm(self, vm, bindings=None):
        from .g17p_uapi import (
            DRM_ASAHI_BIND_SINGLE_PAGE,
            DRM_ASAHI_BIND_WRITE,
        )

        front = self.front
        context = int(vm.token)
        state = front.g17p.execution_contexts[context]
        changed = False
        selected = vm.bindings if bindings is None else bindings
        for binding in selected:
            if binding.token["mapping"] is not None:
                continue
            pa = self._bo_pa(binding.bo) + binding.bo_offset
            address = self._render_dva(binding.addr)
            binding.token["mapping"] = state["space"].map_existing_at(
                address,
                pa,
                binding.size,
                "modern GEM %d" % binding.bo.handle,
                single_page=bool(
                    binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE),
                # G17P uses this leaf class split for GPU read-only command and
                # program pages versus writable resources.
                UXN=(1 if binding.flags & DRM_ASAHI_BIND_WRITE else 0),
            )
            changed = True
        if changed:
            state["space"].flush()
            front.g17p.u.inst("dsb sy")
            front.g17p.u.inst("tlbi aside1os, x0", context << 48)
            front.g17p.u.inst("dsb sy")

    def create_queue(self, _file, queue):
        token = {
            "context": int(queue.vm.token),
            "priority": queue.priority,
            "usc_exec_base": queue.usc_exec_base,
        }
        if os.getenv("G17P_ALLOW_INTERNAL_RENDER_POINTERS") == "1":
            token["resolve_internal_range"] = (
                lambda address, size, required, label:
                self._resolve_internal_render_range(
                    queue, address, size, required, label)
            )
        return token

    def _resolve_internal_render_range(
            self, queue, address, size, _required, label):
        """Accept an explicitly enabled backend-owned render mapping."""
        if not label.startswith("render "):
            return False
        ranges = self.front.g17p.space.uat.iotranslate(
            int(queue.vm.token), int(address), int(size))
        remaining = int(size)
        for pa, span in ranges:
            if pa is None:
                return False
            remaining -= min(remaining, span)
            if not remaining:
                return True
        return False

    def destroy_queue(self, _file, _queue):
        # The serialized backend shares firmware queues. The logical queue and
        # all of its fences have ended before this device-lifetime no-op.
        return None

    def preflight(self, _file, _queue, commands):
        """Reject command state not yet represented by the native builders."""
        return None

    @staticmethod
    def _bindings_for(vm, address, size):
        end = int(address) + int(size)
        cursor = int(address)
        matches = []
        for binding in vm.bindings:
            if binding.end <= cursor:
                continue
            if binding.addr > cursor:
                break
            matches.append(binding)
            cursor = min(end, binding.end)
            if cursor == end:
                return tuple(matches)
        raise G17PUnsupported(
            "GPU range %#x..%#x is not completely covered by VM bindings" %
            (address, end))

    @classmethod
    def _binding_for(cls, vm, address, size):
        matches = cls._bindings_for(vm, address, size)
        if len(matches) != 1:
            raise G17PUnsupported(
                "GPU range %#x..%#x is not covered by one VM binding" %
                (address, int(address) + int(size)))
        return matches[0]

    def _push_vm(self, vm):
        seen = set()
        for binding in vm.bindings:
            bo = binding.bo
            if bo.handle in seen:
                continue
            seen.add(bo.handle)
            pa = self._bo_pa(bo)
            self.front.g17p.space.write(pa, bytes(bo.token["map"][:bo.size]))

    def _push_timestamp_objects(self, file):
        for obj in file.objects.values():
            token = obj.token
            if token["pa"] is None:
                token["pa"] = self._bo_pa(obj.bo) + obj.offset
            if not token["mapped"]:
                self.front.g17p.map_firmware_existing_at(
                    token["address"], token["pa"], token["size"])
                token["mapped"] = True
            self.front.g17p.space.write(
                token["pa"],
                bytes(obj.bo.token["map"][obj.offset:obj.offset + obj.size]))

    def _pull_timestamp_objects(self, objects):
        seen = set()
        for obj in objects:
            if id(obj) in seen:
                continue
            seen.add(id(obj))
            token = obj.token
            data = self.front.g17p.space.read(token["pa"], obj.size)
            obj.bo.token["map"][obj.offset:obj.offset + obj.size] = data

    def _pull_attachments(self, vm, attachments):
        seen = set()
        for attachment in attachments:
            for binding in self._bindings_for(
                    vm, int(attachment.pointer), int(attachment.size)):
                bo = binding.bo
                if bo.handle in seen:
                    continue
                seen.add(bo.handle)
                pa = self._bo_pa(bo)
                data = self.front.g17p.space.read(pa, bo.size)
                bo.token["map"][:bo.size] = data

    def _pull_render_writable_bindings(self, vm):
        """Synchronize every BO the render VM allows hardware to write.

        Render attachments are optional firmware scheduling hints in the UAPI;
        they are not a complete memory-write declaration.  In particular, ZLS
        depth/stencil buffers are command fields and need not be repeated as
        fragment attachments.  Copy back all writable bindings after the
        synchronous render fence instead of making correctness depend on hints.
        """
        from .g17p_uapi import DRM_ASAHI_BIND_WRITE

        seen = set()
        for binding in vm.bindings:
            if not binding.flags & DRM_ASAHI_BIND_WRITE:
                continue
            bo = binding.bo
            if bo.handle in seen:
                continue
            seen.add(bo.handle)
            pa = self._bo_pa(bo)
            data = self.front.g17p.space.read(pa, bo.size)
            bo.token["map"][:bo.size] = data

    @staticmethod
    def _timestamp_addresses(command):
        return {
            name: obj.token["address"] + offset
            for name, obj, offset in command.timestamp_objects
        }

    def _apply_render_transport_oracle(self, drm):
        """Replace only hardware-private render fields for the shim smoke.

        The modern UAPI resolver has already validated and retained every BO
        referenced by the caller's real command. Keeping the caller's color
        attachment, VM, logical queue, priority, and synchronization while
        replacing its currently G13/G14-specific program graph isolates the
        DRM-shim and firmware-ABI boundary from the unfinished Apple9 compiler.
        """
        if not self.front.g17p_render_transport_oracle:
            return False
        if (drm.fb_width, drm.fb_height, drm.layers) != (64, 64, 1):
            raise G17PUnsupported(
                "G17P DRM transport oracle requires one 64x64 layer")
        if drm.attachment_count != 1 or drm.attachments[0].size < 0x4000:
            raise G17PUnsupported(
                "G17P DRM transport oracle requires one 16 KiB color attachment")

        original = (
            drm.encoder_ptr,
            drm.load_pipeline,
            drm.store_pipeline,
            drm.partial_reload_pipeline,
            drm.partial_store_pipeline,
        )
        for name, value in self.TRANSPORT_ORACLE.items():
            setattr(drm, name, value)
        drm.ds_flags = 0
        drm.depth_buffer = 0
        drm.depth_aux_buffer = 0
        drm.depth_stride = 0
        drm.depth_aux_stride = 0
        drm.stencil_buffer = 0
        drm.stencil_aux_buffer = 0
        drm.stencil_stride = 0
        drm.stencil_aux_stride = 0
        drm.occlusion_query_base = 0
        drm.isp_zls_pixels = 0
        drm.isp_merge_upper_x = 0
        drm.isp_merge_upper_y = 0
        drm.depth_clear_value_bits = 0
        drm.stencil_clear_value = 0
        drm.sampler_array = 0
        drm.sampler_count = 0
        drm.process_empty_tiles = True
        drm.aux_fb_flags = 0xC001
        self.front.log(
            "G17P DRM TRANSPORT ORACLE: validated caller render; "
            "program graph (%#x,%#x,%#x,%#x,%#x) -> "
            "known G17P recipe; attachment=%#x/%#x" % (
                *original,
                drm.attachments[0].pointer,
                drm.attachments[0].size,
            ))
        return True

    def _submit_render(self, queue, command):
        import types

        front = self.front
        if (getattr(front, "g17p_direct_bootstrap", None) is not None
                and not getattr(front.g17p, "runtime_prepared", False)):
            # Direct bootstrap executes compute after firmware start. Its
            # deliberately un-rung opening TA/3D pair is consumed and removed
            # during startup, so the first real render uses the normal runtime
            # pair instead of trying to resurrect slot zero.
            front.g17p.prepare_submission_runtime(reset_staged=False)
            front.g17p.forced_queue_pair = 1
            front.g17p.group_number = max(front.g17p.group_number, 1)
        payload = command.payload
        state = command.hardware_state
        fragment_attachments = command.fragment_attachments
        modern_attachments = []
        attachment_objects = []
        for attachment in fragment_attachments:
            binding = self._binding_for(
                queue.vm, int(attachment.pointer), int(attachment.size))
            modern_attachments.append(types.SimpleNamespace(
                type=0, pointer=int(attachment.pointer),
                size=int(attachment.size)))
            attachment_objects.append(types.SimpleNamespace(
                # The UAPI hint may name a subrange of a larger VM binding.
                # submit_drm validates exact hint pointers, so describe that
                # subrange rather than incorrectly substituting the binding's
                # base DVA.
                _addr=int(attachment.pointer),
                _size=int(attachment.size), _destroyed=False))
        timestamps = self._timestamp_addresses(command)
        drm = types.SimpleNamespace(
            flags=state.flags,
            encoder_ptr=self._render_dva(state.vdm_base),
            encoder_id=0, cmd_ta_id=0, cmd_3d_id=0,
            ds_flags=state.zls_ctrl,
            depth_buffer=state.depth_base,
            depth_aux_buffer=state.depth_comp_base,
            depth_stride=state.depth_stride,
            depth_aux_stride=state.depth_comp_stride,
            stencil_buffer=state.stencil_base,
            stencil_aux_buffer=state.stencil_comp_base,
            stencil_stride=state.stencil_stride,
            stencil_aux_stride=state.stencil_comp_stride,
            scissor_array=state.scissor_base,
            depth_bias_array=state.dbias_base,
            occlusion_query_base=state.oclqry_base,
            ppp_multisamplectl=state.multisample_control,
            ppp_ctrl=state.ppp_control,
            utile_width=state.utile_width,
            utile_height=state.utile_height,
            samples=state.samples,
            sample_size=state.sample_size,
            iogpu_unk_49=state.blocks_per_utile,
            fb_width=state.width,
            fb_height=state.height,
            layers=state.layers,
            utile_config=state.utile_config,
            tile_config=state.tile_config,
            isp_zls_pixels=int(payload.isp_zls_pixels),
            isp_merge_upper_x=state.merge_upper_x,
            isp_merge_upper_y=state.merge_upper_y,
            load_pipeline=state.bg_usc,
            load_pipeline_bind=state.bg_rsrc_spec,
            store_pipeline=state.eot_usc,
            store_pipeline_bind=state.eot_rsrc_spec,
            partial_reload_pipeline=state.partial_bg_usc,
            partial_reload_pipeline_bind=state.partial_bg_rsrc_spec,
            partial_store_pipeline=state.partial_eot_usc,
            partial_store_pipeline_bind=state.partial_eot_rsrc_spec,
            depth_clear_value_bits=state.bgobjdepth,
            stencil_clear_value=state.bgobjvals,
            sampler_array=state.sampler_heap,
            sampler_count=state.sampler_count,
            process_empty_tiles=bool(
                state.flags & (1 << 1)),
            # The native eight-R32F partial workload carries 0xc000 here;
            # retained one-target renders carry 0xc001.  This is descriptor
            # command state, distinct from the attachment lifetime hints.
            aux_fb_flags=((0xc000 if len(modern_attachments) > 1 else 0xc001)
                          | (state.flags & (1 << 18))),
            usc_exec_base=state.usc_exec_base,
            emit_uapi_fields=True,
            attachments=tuple(modern_attachments),
            attachment_count=len(modern_attachments),
        )
        self._apply_render_transport_oracle(drm)
        supplied = front.g17p_supplied()
        supplied.update(
            ta_user_timestamp_start=timestamps.get("vertex_start", 0),
            ta_user_timestamp_end=timestamps.get("vertex_end", 0),
            fragment_user_timestamp_start=timestamps.get("fragment_start", 0),
            fragment_user_timestamp_end=timestamps.get("fragment_end", 0),
        )
        submission = front.g17p.submit_drm(
            drm, tuple(attachment_objects), context_id=int(queue.vm.token),
            firmware_priority=int(queue.priority),
            **supplied)
        fence = front.g17p.pair_fence(
            submission,
            name="modern render command %d" % command.index,
            metadata={
                "vm_id": int(queue.vm.vm_id),
                "queue_id": int(queue.queue_id),
                "command_index": int(command.index),
                "command_type": int(command.header.cmd_type),
            },
        )
        # The modern adapter serializes commands and copies render results back
        # before returning the submission.  Release the completed pair's
        # intrusive scheduler list here as well: a linked render job list is a
        # deliberate diagnostic state, but it blocks the proven render-to-CL2
        # transition used by mixed Mesa submissions.
        if fence.signaled() and fence.error is None:
            front.g17p.quiesce_submission(
                submission, semantic_complete=True)
            self.render_since_compute = True
        return fence

    @staticmethod
    def _compute_experiment_path():
        import importlib
        import pathlib

        path = pathlib.Path(__file__).resolve().parents[2] / "experiments"
        path = str(path)
        if path not in sys.path:
            sys.path.insert(0, path)
        return importlib, path

    def _load_compute_render_helper(self):
        """Load only the helper that leaves the final-26.6 opening intact."""
        importlib, _path = self._compute_experiment_path()
        return importlib.import_module("agx_g17p_compute")

    def _load_compute_helpers(self):
        """Load compute builders after the ordinary render transition."""
        importlib, _path = self._compute_experiment_path()
        return {
            "compute": importlib.import_module("agx_g17p_compute"),
            "native": importlib.import_module("agx_g17p_native_add3"),
            "source": importlib.import_module(
                "agx_g17p_compute_source_initial"),
        }

    def _mirror_compute_vm(self, vm, runtime):
        """Expose caller BO backing through compute's admitted contexts 2/3."""
        from m1n1.hw.uat import MemoryAttr
        from .g17p_uapi import (
            DRM_ASAHI_BIND_SINGLE_PAGE,
            DRM_ASAHI_BIND_WRITE,
        )

        client = runtime["client"]
        space = client["space"]
        page = space.uat.PAGE_SIZE
        native_context = runtime["native"].CONTEXT
        mirrored = runtime.setdefault("compute_vm_pages", {})
        added = False
        changed = []
        for binding in vm.bindings:
            single = bool(binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE)
            for offset in range(0, binding.size, page):
                address = int(binding.addr) + offset
                pa = mirrored.get(address)
                translated = space.uat.iotranslate_root(
                    space.uat.ttbr0_base, address, page)
                current = (
                    translated[0][0]
                    if len(translated) == 1 and translated[0][1] == page
                    else None)
                if pa is None:
                    if current is None:
                        backing = self._bo_pa(binding.bo) + binding.bo_offset
                        pa = backing if single else backing + offset
                        space.uat.iomap_at(
                            native_context,
                            address,
                            pa,
                            page,
                            AttrIndex=MemoryAttr.Shared,
                            AP=2,
                            nG=1,
                            # On G17P this leaf bit follows GPU write
                            # permission, not CPU execute permission.
                            UXN=(1 if binding.flags & DRM_ASAHI_BIND_WRITE
                                 else 0),
                            OS=1,
                        )
                        added = True
                    else:
                        # The field-built client graph already owns this DVA.
                        # Preserve its physical identity; firmware may retain
                        # it from registration before the caller command.
                        pa = current
                    mirrored[address] = pa
                elif current != pa:
                    raise RuntimeError(
                        "compute DVA %#x changed backing from %#x to %s" % (
                            address, pa,
                            "unmapped" if current is None else "%#x" % current,
                        ))

                source = int(binding.bo_offset) + (0 if single else offset)
                length = min(page, int(binding.size) - offset)
                body = bytes(
                    binding.bo.token["map"][source:source + length])
                if space.read(pa, length) != body:
                    space.write(pa, body)
                    changed.append(address)
        if added:
            space.uat.flush_dirty()
            space.uat.invalidate_cache()
        space.flush()
        self.front.g17p.u.inst("dsb sy")
        if added:
            self.front.g17p.u.inst(
                "tlbi aside1os, x0", native_context << 48)
            self.front.g17p.u.inst(
                "tlbi aside1os, x0", (native_context + 1) << 48)
            self.front.g17p.u.inst("dsb sy")

        print(
            "MODERN COMPUTE mirrored %d differing caller page(s): %s" % (
                len(changed),
                ", ".join("%#x" % address for address in changed) or "none",
            ),
            flush=True,
        )

        for binding in vm.bindings:
            translated = space.uat.iotranslate_root(
                space.uat.ttbr0_base, binding.addr, binding.size)
            covered = 0
            for physical, length in translated:
                wanted = mirrored[int(binding.addr) + covered]
                if physical != wanted:
                    raise RuntimeError(
                        "compute DVA %#x resolved to %#x, expected %#x" % (
                            binding.addr + covered,
                            0 if physical is None else physical,
                            wanted,
                        ))
                covered += length
            if covered != binding.size:
                raise RuntimeError(
                    "compute DVA %#x covers %#x bytes, expected %#x" % (
                        binding.addr, covered, binding.size))

    def _pull_compute_attachments(self, vm, attachments, runtime):
        space = runtime["client"]["space"]
        for attachment in attachments:
            start = int(attachment.pointer)
            end = start + int(attachment.size)
            for binding in self._bindings_for(vm, start, end - start):
                copy_start = max(start, int(binding.addr))
                copy_end = min(end, int(binding.end))
                translated = space.uat.iotranslate_root(
                    space.uat.ttbr0_base,
                    copy_start,
                    copy_end - copy_start,
                )
                destination = (
                    int(binding.bo_offset) + copy_start - int(binding.addr))
                copied = 0
                for physical, length in translated:
                    if physical is None:
                        raise RuntimeError(
                            "compute attachment DVA %#x is unmapped" %
                            (copy_start + copied))
                    body = space.read(physical, length)
                    binding.bo.token["map"][
                        destination + copied:destination + copied + length
                    ] = body
                    copied += length

    def _pull_compute_writable_bindings(self, vm, runtime):
        """Synchronize all possible shader writes back to proxy-visible BOs.

        UAPI attachments are optional and may be incomplete for bindless work,
        so they cannot define the copyback set. A single-page binding aliases
        one physical page across its whole DVA range and is copied only once.
        """
        from .g17p_uapi import DRM_ASAHI_BIND_SINGLE_PAGE, DRM_ASAHI_BIND_WRITE

        space = runtime["client"]["space"]
        seen = set()
        for binding in vm.bindings:
            if not binding.flags & DRM_ASAHI_BIND_WRITE:
                continue
            key = id(binding)
            if key in seen:
                continue
            seen.add(key)
            size = int(binding.size)
            if binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE:
                size = min(size, 0x4000)
            translated = space.uat.iotranslate_root(
                space.uat.ttbr0_base, int(binding.addr), size)
            copied = 0
            for physical, length in translated:
                if physical is None:
                    raise RuntimeError(
                        "writable compute DVA %#x is unmapped" %
                        (int(binding.addr) + copied))
                body = space.read(physical, length)
                start = int(binding.bo_offset) + copied
                binding.bo.token["map"][start:start + length] = body
                copied += length
            if copied != size:
                raise RuntimeError(
                    "writable compute DVA %#x copied %#x of %#x bytes" %
                    (int(binding.addr), copied, size))

    @staticmethod
    def _compute_timestamp_pair(command):
        timestamps = _G17PModernHardwareAdapter._timestamp_addresses(command)
        return (timestamps.get("compute_start", 0),
                timestamps.get("compute_end", 0))

    @staticmethod
    def _compute_registers(runtime, command, ordinal, spec, workload):
        from . import g17p_compute

        native = runtime["native"]
        state = command.hardware_state
        command_slot = int(workload["slot"])
        registers = native._registers_for_workload(
            ordinal,
            metadata_ordinal=spec.get("metadata_ordinal"),
            command_slot=command_slot,
            indirect_dispatch=False,
            resource_base=runtime["client"]["resource_base"],
            cdm_base=runtime["client"]["cdm_base"],
        )
        if os.getenv("G17P_MODERN_NATIVE_COMPUTE_REGISTERS") == "1":
            return registers
        return g17p_compute.apply_compute_uapi_registers(
            registers,
            preempt_base=(runtime["client"]["resource_base"]
                          + command_slot * native.CLIENT_WORKLOAD_STRIDE),
            cdm_base=state.cdm_base,
            usc_exec_base=state.usc_exec_base,
            helper_binary=state.helper_binary,
            helper_data=state.helper_data,
            helper_cfg=state.helper_cfg,
        )

    def _start_compute_runtime(self, queue, command, force_fresh=False):
        front = self.front
        backend = front.g17p
        direct_bootstrap = getattr(front, "g17p_direct_bootstrap", None)
        if direct_bootstrap is not None and not force_fresh:
            helpers = self._load_compute_helpers()
            client = direct_bootstrap["client"]
            client["user_timestamp_addresses"] = {
                ordinal: (0, 0) for ordinal in range(258)
            }
            runtime = {
                **helpers,
                "client": client,
                "queue": direct_bootstrap["queue"],
                "ordinal": int(direct_bootstrap["completed_ordinal"]) + 1,
                "vm": queue.vm,
                "runtime_tick_staged": False,
                "native_baseline": False,
                "admission_bootstrap": False,
                "initial_group_number": 1,
                "baseline_result": None,
                "retained_direct_bootstrap": True,
            }
            self._mirror_compute_vm(queue.vm, runtime)
            self.compute_runtime = runtime
            print(
                "MODERN COMPUTE adopted retained direct lifetime after "
                "workload %d" % direct_bootstrap["completed_ordinal"],
                flush=True,
            )
            return runtime

        compute_helper = self._load_compute_render_helper()
        admission_bootstrap = (
            not force_fresh and
            os.getenv("G17P_MODERN_SKIP_ADMISSION") != "1")

        if not force_fresh:
            compute_helper.drain_boot_group(front, backend)
        transition_pa = transition_before = transition_after = None
        if admission_bootstrap:
            cadence = compute_helper.create_render_cadence_workload(front)
            transition = compute_helper.run_render_cadence_submission(
                front,
                backend,
                cadence,
                "modern pre-compute transition render",
            )
            transition_fence = backend.pair_fence(
                transition, name="modern pre-compute transition render")
            transition_fence.wait(
                timeout=0.2, event_pump=backend.event_pump)
            if not transition_fence.signaled():
                raise RuntimeError(
                    "modern pre-compute transition render did not retire")
            transition_pa = transition["semantic_witness_pa"]
            transition_before = bytes(backend.space.uat.PAGE_SIZE)
            backend.u.proxy.dc_ivac(
                transition_pa, backend.space.uat.PAGE_SIZE)
            transition_after = bytes(backend.u.iface.readmem(
                transition_pa, backend.space.uat.PAGE_SIZE))
            backend.quiesce_submission(transition, semantic_complete=True)
        helpers = self._load_compute_helpers()
        native = helpers["native"]
        runtime_ordinal = 0
        graph_item_capacity = 1
        if admission_bootstrap:
            import math
            import struct
            from m1n1.hw.uat import MemoryAttr

            baseline_client = native.build_client_graph(
                backend,
                distinct_empty_high=True,
                native_shader_attributes=True,
                workload_count=1,
                client_slot_count=1,
                indirect_dispatch=True,
                indirect_layout="native",
            )
            baseline_client["user_timestamp_addresses"] = {
                ordinal: (0, 0) for ordinal in range(258)
            }
            baseline_queue = native.build_firmware_graph(
                backend,
                baseline_client["terminator"],
                baseline_client["space"],
                alias_context0_queue=True,
                item_capacity=2,
                indirect_dispatch=True,
                resource_base=baseline_client["resource_base"],
                cdm_base=baseline_client["cdm_base"],
                user_timestamp_addresses=(
                    baseline_client["user_timestamp_addresses"]),
            )
            dependency = None
            for offset in range(0, len(transition_after) - 256 + 1, 4):
                body = transition_after[offset:offset + 256]
                values = struct.unpack("<64f", body)
                if (body != transition_before[offset:offset + 256]
                        and all(math.isfinite(value) for value in values)):
                    dependency = offset, values
                    break
            if dependency is None:
                raise RuntimeError(
                    "modern transition render has no finite dependency window")
            dependency_alias = 0x10008000000
            baseline_client["space"].uat.iomap_at(
                native.CONTEXT,
                dependency_alias,
                transition_pa,
                backend.space.uat.PAGE_SIZE,
                AttrIndex=MemoryAttr.Shared,
                AP=2,
                nG=1,
                UXN=1,
                OS=1,
            )
            baseline_client["space"].uat.flush_dirty()
            baseline_client["space"].uat.invalidate_cache()
            backend.u.proxy.dc_civac(
                transition_pa, backend.space.uat.PAGE_SIZE)
            backend.u.inst(
                "dsb sy; tlbi aside1os, x0; dsb sy; isb",
                native.CONTEXT << 48,
            )
            prepared = native.prepare_client_workload(
                baseline_client,
                0,
                input_a_dependency={
                    "expected": dependency[1],
                    "output_dva": dependency_alias + dependency[0],
                },
            )
            baseline_client["expected"] = prepared["expected"]
            baseline_client["output_pa"] = prepared["output_pa"]
            baseline_client["space"].flush()
            backend.u.inst("dsb sy")
        if not force_fresh:
            helpers["source"].seed_completed_control_history(backend)
        else:
            control = backend.channels.entries[
                helpers["compute"].g17p.CHANNEL_TABLE_WORK_COUNT]
            counters = backend.channels.counters(control)
            if counters[0] != counters[1] or counters[1] != counters[2]:
                raise RuntimeError(
                    "post-render compute control history is not retired: %r" %
                    counters)
            print(
                "MODERN COMPUTE retained completed post-render control "
                "history at %r" % counters,
                flush=True,
            )
        baseline_result = None
        if admission_bootstrap:
            baseline_result = native.submit_built(
                front, backend, baseline_client, queue=baseline_queue)

        client = native.build_client_graph(
            backend,
            distinct_empty_high=True,
            native_shader_attributes=True,
            workload_count=1,
            client_slot_count=1,
            indirect_dispatch=False,
        )
        runtime = {
            **helpers,
            "client": client,
            "queue": None,
            "ordinal": runtime_ordinal,
            "vm": queue.vm,
            "runtime_tick_staged": False,
            "native_baseline": False,
            "admission_bootstrap": admission_bootstrap,
            "initial_group_number": 2 if admission_bootstrap else 1,
            "baseline_result": baseline_result,
            "initial_require_virgin": not force_fresh,
        }
        self._mirror_compute_vm(queue.vm, runtime)

        state = command.hardware_state
        client["user_timestamp_addresses"] = {
            ordinal: (0, 0) for ordinal in range(258)
        }
        client["user_timestamp_addresses"][runtime_ordinal] = (
            self._compute_timestamp_pair(command))
        initial_workload = {
            "slot": 0,
            "terminator": state.cdm_terminator,
        }
        registers = self._compute_registers(
            runtime, command, 0, native._work_addresses(0), initial_workload)
        work_queue = native.build_firmware_graph(
            backend,
            state.cdm_terminator,
            client["space"],
            alias_context0_queue=True,
            item_capacity=graph_item_capacity,
            indirect_dispatch=False,
            resource_base=client["resource_base"],
            cdm_base=state.cdm_base,
            user_timestamp_addresses=client["user_timestamp_addresses"],
            initial_registers=registers,
            sampler_array=state.sampler_heap,
            sampler_count=state.sampler_count,
        )
        client["sampler_array"] = state.sampler_heap
        client["sampler_count"] = state.sampler_count
        runtime["queue"] = work_queue
        self.compute_runtime = runtime
        if force_fresh:
            print(
                "MODERN COMPUTE built a rebased first-generation CL2 graph "
                "after render quiescence (physical ordinal 0)",
                flush=True,
            )
        return runtime

    def _submit_compute(self, queue, command):
        force_fresh = self.render_since_compute
        if force_fresh:
            acknowledged = self.front.g17p.acknowledge_report_channels()
            print(
                "MODERN COMPUTE returned post-render report credits: "
                "touched=%d" % len(acknowledged),
                flush=True,
            )
            self.compute_runtime = None
        runtime = self.compute_runtime
        if runtime is None:
            runtime = self._start_compute_runtime(
                queue, command, force_fresh=force_fresh)
        elif runtime["vm"] is not queue.vm:
            raise G17PUnsupported(
                "G17P compute currently supports one live VM")
        else:
            self._mirror_compute_vm(queue.vm, runtime)

        native = runtime["native"]
        state = command.hardware_state
        ordinal = int(runtime["ordinal"])
        runtime["command"] = command
        runtime["client"]["sampler_array"] = state.sampler_heap
        runtime["client"]["sampler_count"] = state.sampler_count
        runtime["client"]["user_timestamp_addresses"][ordinal] = (
            self._compute_timestamp_pair(command))
        def prepare_workload(item_ordinal):
            if os.getenv("G17P_MODERN_NATIVE_COMPUTE_PREPARE") == "1":
                prepared = native.prepare_client_workload(
                    runtime["client"], item_ordinal)
                self._mirror_compute_vm(queue.vm, runtime)
                prepared["terminator"] = state.cdm_terminator
                return prepared
            return {
                "slot": (int(item_ordinal) %
                         len(runtime["client"]["terminators"])),
                "terminator": state.cdm_terminator,
            }

        runtime["client"]["prepare_workload"] = prepare_workload
        runtime["client"]["register_builder"] = (
            lambda item_ordinal, spec, workload:
            self._compute_registers(
                runtime, runtime["command"], item_ordinal, spec, workload))

        if ordinal == 0:
            if (runtime["admission_bootstrap"] and
                    not runtime["runtime_tick_staged"]):
                self.front.g17p_runtime["stage_runtime_tick"](
                    0,
                    "modern compute initial runtime tick",
                    context_word=native.CONTEXT,
                    update_sequence=True,
                )
                runtime["runtime_tick_staged"] = True
            prepared = native.stage_built(
                self.front.g17p,
                runtime["queue"],
                group_number=runtime["initial_group_number"],
                require_virgin=runtime.get(
                    "initial_require_virgin",
                    not runtime["admission_bootstrap"]),
            )
            queue_fence = prepared["fence_object"]
        else:
            before_publish = None
            retained_direct = runtime.get("retained_direct_bootstrap", False)
            if (ordinal > 1 and not retained_direct
                    and not runtime["runtime_tick_staged"]):
                def before_publish():
                    self.front.g17p_runtime["stage_runtime_tick"](
                        0,
                        "modern compute initial runtime tick",
                        context_word=native.CONTEXT,
                        update_sequence=True,
                    )
                runtime["runtime_tick_staged"] = True
            options = {}
            if retained_direct:
                options.update(
                    persistent_runtime_queue=True,
                    persistent_startup_queue=True,
                    persistent_runtime_fresh_descriptors=True,
                    persistent_runtime_fresh_events=True,
                    fast_sequential=True,
                    strict_release_publish=True,
                )
            elif ordinal > 1:
                options.update(
                    persistent_runtime_queue=True,
                    persistent_startup_queue=False,
                    persistent_runtime_optional_once=True,
                    persistent_runtime_fresh_descriptors=True,
                    fast_sequential=True,
                    strict_release_publish=True,
                )
            prepared = native.stage_next_workload(
                self.front.g17p,
                runtime["client"],
                runtime["queue"],
                ordinal,
                before_publish=before_publish,
                **options,
            )
            queue_fence = prepared["fence"]

        fence = self.front.g17p.fence_tracker.track(
            (queue_fence,),
            name="modern compute command %d" % command.index,
            metadata={
                "context_id": int(queue.vm.token),
                "vm_id": int(queue.vm.vm_id),
                "queue_id": int(queue.queue_id),
                "command_index": int(command.index),
                "command_type": int(command.header.cmd_type),
                "submission_ordinal": ordinal,
            },
        )

        import time
        fence.wait(timeout=0.2, event_pump=self.front.g17p.event_pump)
        if not fence.signaled():
            raise RuntimeError(
                "modern compute command %d did not retire" % command.index)
        if fence.error is not None:
            # A fatal RTKit notification is itself the terminal point.  There
            # will be no later command status write or safe BO copyback.
            runtime["ordinal"] = ordinal + 1
            return fence
        # Queue/channel retirement releases the transport slots before the
        # command-local completion word becomes visible.  The latter is the
        # semantic completion point observed by successful source submissions.
        deadline = time.monotonic() + 0.2
        while (not queue_fence.status_changed()
               and time.monotonic() < deadline):
            if self.front.g17p.event_pump is not None:
                self.front.g17p.event_pump()
            time.sleep(0.0001)
        if not queue_fence.status_changed():
            raise RuntimeError(
                "modern compute command %d retired without a completion "
                "status transition: %r" % (
                    command.index, queue_fence.snapshot()))
        output = runtime["client"]["objects"].get("output")
        if output is not None:
            output_dva, original_pa, _size = output
            current_pa = runtime["client"]["space"].uat.iotranslate_root(
                runtime["client"]["space"].uat.ttbr0_base,
                output_dva,
                0x100,
            )[0][0]
            original = self.front.g17p.space.read(original_pa, 0x100)
            current = self.front.g17p.space.read(current_pa, 0x100)
            print(
                "MODERN COMPUTE witness: fence=%r output DVA %#x "
                "original PA %#x changed=%d selected PA %#x changed=%d" % (
                    fence.snapshot(), output_dva, original_pa,
                    sum(value != 0 for value in original), current_pa,
                    sum(value != 0 for value in current)),
                flush=True,
            )
        runtime["ordinal"] = ordinal + 1
        self._pull_compute_writable_bindings(queue.vm, runtime)
        self.render_since_compute = False
        return fence

    def submit(self, file, queue, commands):
        from .g17p_sync import G17PSubmissionFence
        from .g17p_uapi import DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_CMD_RENDER

        front = self.front
        if (getattr(front, "g17p_source_partial_integration", False)
                and not getattr(front, "g17p_source_partial_consumed", False)):
            if front.initialized:
                raise RuntimeError(
                    "source-partial integration initialized before submit")
            renders = tuple(
                command for command in commands
                if command.header.cmd_type == DRM_ASAHI_CMD_RENDER)
            if len(commands) != 1 or len(renders) != 1:
                raise G17PUnsupported(
                    "source-partial integration requires one render command")
            command = renders[0]
            if len(command.fragment_attachments) != 1:
                raise G17PUnsupported(
                    "source-partial integration requires one color attachment")
            attachment = command.fragment_attachments[0]
            binding = self._binding_for(
                queue.vm, int(attachment.pointer), int(attachment.size))
            if int(binding.bo_offset) or int(binding.bo.size) != 0x4000:
                raise G17PUnsupported(
                    "source-partial integration requires one aligned 16 KiB BO")
            front.g17p_partial_integration_output_bo = binding.bo
            front.log(
                "G17P SOURCE PARTIAL INTEGRATION: validated Mesa render; "
                "cold-publishing source-built partial work into GEM %d" %
                binding.bo.handle)
            front.init()
            if binding.bo.token.get("pa") is None:
                raise RuntimeError(
                    "source-partial integration did not assign caller backing")
            body = front.g17p.space.read(
                binding.bo.token["pa"], binding.bo.size)
            binding.bo.token["map"][:binding.bo.size] = body
            front.g17p_source_partial_consumed = True
            from .g17p_sync import G17PSoftwareFence
            return G17PSubmissionFence(
                (G17PSoftwareFence(signaled=True),),
                name="source-built first-partial Mesa submission",
                metadata={
                    "vm_id": int(queue.vm.vm_id),
                    "queue_id": int(queue.queue_id),
                    "command_index": int(command.index),
                    "command_type": int(command.header.cmd_type),
                },
            )
        if (self.compute_runtime is None
                and not self.render_since_compute
                and not any(command.header.cmd_type == DRM_ASAHI_CMD_RENDER
                            for command in commands)):
            first_compute = next(
                (command for command in commands
                 if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE),
                None,
            )
            if first_compute is not None:
                # The opening render still consumes the default USC pages.
                # Drain it before a caller is allowed to replace those VAs.
                self._start_compute_runtime(queue, first_compute)
        native_baseline = bool(
            self.compute_runtime is not None
            and self.compute_runtime.get("native_baseline"))
        retained_compute_only = bool(
            self.compute_runtime is not None
            and self.compute_runtime.get("retained_direct_bootstrap")
            and all(command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE
                    for command in commands)
        )
        if not retained_compute_only:
            front.g17p.activate_execution_context(int(queue.vm.token))
        if not retained_compute_only:
            self._push_vm(queue.vm)
        self._push_timestamp_objects(file)
        render_commands = tuple(
            command for command in commands
            if command.header.cmd_type == DRM_ASAHI_CMD_RENDER)
        if render_commands:
            render_bindings = None
            if front.g17p_render_transport_oracle:
                # The original Mesa graph was fully resolved above, but the
                # compatibility recipe executes entirely from backend-owned
                # addresses.  Install only its caller-visible output hints in
                # the live retained context; mapping unrelated Mesa program
                # BOs can replace retained render-graph leaves.
                render_bindings = []
                seen = set()
                for command in render_commands:
                    for attachment in command.fragment_attachments:
                        for binding in self._bindings_for(
                                queue.vm, int(attachment.pointer),
                                int(attachment.size)):
                            if id(binding) in seen:
                                continue
                            seen.add(id(binding))
                            render_bindings.append(binding)
                front.log(
                    "G17P DRM TRANSPORT ORACLE: mapping %d attachment "
                    "binding(s), excluding %d validated caller binding(s)" % (
                        len(render_bindings),
                        len(queue.vm.bindings) - len(render_bindings)))
            self._ensure_render_vm(queue.vm, render_bindings)
        command_fences = []
        for command in commands:
            if command.header.cmd_type == DRM_ASAHI_CMD_RENDER:
                command_fence = self._submit_render(queue, command)
                command_fences.append(command_fence)
                if command_fence.error is not None:
                    break
                self._pull_render_writable_bindings(queue.vm)
            elif command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE:
                command_fence = self._submit_compute(queue, command)
                command_fences.append(command_fence)
                if command_fence.error is not None:
                    break
            else:
                raise AssertionError("parser returned a software command")
        resources = []
        seen = set()
        for command in commands:
            for _name, obj, _offset in command.timestamp_objects:
                if id(obj) not in seen:
                    seen.add(id(obj))
                    resources.append(obj)
        if not self.device_lost:
            self._pull_timestamp_objects(resources)
        fence = G17PSubmissionFence(
            command_fences,
            name="modern Asahi submit",
            metadata={"queue_id": queue.queue_id,
                      "context_id": int(queue.vm.token)},
        )
        for obj in resources:
            obj.token["fences"].append(fence)
        self._reap_timestamp_allocations()
        return fence


class DRMAsahiShim:
    G17P_COLD_BOOT_ARGS = (
        "--timeout", "20", "--read-crash", "--no-registers",
        "--build-dispatch", "--build-records", "--publish-after-control",
        "--no-announce", "--separate-blank-pages", "--macos-context-table",
        "--split-context", "never", "--graft", "none", "--no-seed", "all",
        "--require-zero-capture-pages", "--full-render-extent",
        "--fast-render-witness", "--no-first-doorbell",
        "--skip-input-completeness", "--skip-leaf-audit",
    )
    # Hardware-proven G17P bring-up and single-context publication behavior.
    # Keep diagnostics overridable, but make ordinary DRM-shim callers use the
    # established path without reproducing a long experiment environment.
    G17P_DEFAULTS = {
        "G17P_COLD_BOOT": "1",
        "G17P_FINAL_26_6_CONTROL_LIFECYCLE": "1",
        "G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE": "1",
        "G17P_LOGICAL_VM_SWITCH": "1",
        "G17P_LOGICAL_VM_STRIDE": "0",
        "G17P_REUSE_QUEUE_ITEMS": "0",
        "G17P_ALTERNATE_QUEUE_PAIRS": "1",
        "G17P_RUNTIME_CURRENT_JOB_RECORDS": "1",
        "G17P_RUNTIME_PAIR_REGISTRATION": "1",
        "G17P_FINAL_26_6_RUNTIME_PAIR": "1",
        "G17P_RUNTIME_PAIR_GROWTH": "1",
        "G17P_RUNTIME_LOW_ROOT_GROWTH": "1",
        "G17P_WAIT_CHANNEL_COMPLETION": "1",
        "G17P_NATIVE_LIFECYCLE_FIELDS": "1",
        "G17P_NATIVE_TAIL_ITEM_FIELDS": "1",
        "G17P_KEEP_BASE_DESCRIPTOR_MIRRORS": "1",
        "G17P_LOCAL_ITEM_REGISTERS": "1",
        "G17P_STRUCTURAL_TAIL_FIELDS": "1",
        "G17P_GROUP_IDENTITY": "0",
        "G17P_NATIVE_STATUS_REGISTERS": "1",
        "G17P_NATIVE_STATUS_ALIASES": "1",
        "G17P_NATIVE_LEAF_LIFECYCLE": "1",
        "G17P_NATIVE_LEAF_PUBLICATION": "1",
        "G17P_NATIVE_STATUS_PUBLICATION": "1",
        "G17P_NATIVE_SHARED_INNER_SEQUENCE": "1",
        "G17P_NATIVE_SCHEDULER_PUBLICATION": "1",
        "G17P_NATIVE_PB_RELEASE_PREVIOUS": "1",
        "G17P_RUNTIME_NATIVE_SHARED_PRESTATE": "1",
        "G17P_SHARE_BOUND_SUBMISSION_STATE": "1",
        "G17P_SHARE_BOUND_RECORD_POOLS": "1",
    }

    def __init__(self, memfd):
        self.memfd = memfd
        self.initialized = False
        self.ioctl_map = {}
        for key in dir(self):
            f = getattr(self, key)
            ioctl = getattr(f, "_ioctl", None)
            if ioctl is not None:
                self.ioctl_map[ioctl.value] = ioctl, f
        self.bos = {}
        self.pull_buffers = bool(os.getenv("ASAHI_SHIM_PULL"))
        self.dump_frames = bool(os.getenv("ASAHI_SHIM_DUMP"))
        self.frame = 0
        self.agx = None
        self.g17p = None
        self.g17p_direct_bootstrap = None
        self.g17p_modern_entrypoint = False
        self.g17p_render_transport_oracle = False
        self.g17p_deferred_modern = False
        self.g17p_source_partial_integration = False
        self.g17p_source_partial_consumed = False
        self.g17p_partial_integration_output_bo = None
        self.renderer = None
        self.g17p_pipeline_image = None
        self.g17p_code_image = None
        self.g17p_fd_contexts = {}
        self.g17p_next_context = 1
        self.g17p_modern_vm_contexts = {}
        from .g17p_modern import G17PModernDriver
        self.modern = G17PModernDriver(_G17PModernHardwareAdapter(self))

    def modern_enable(self):
        """Select the source-built modern-UAPI cold boot before first use."""
        if self.initialized:
            return -errno.EBUSY
        self.g17p_modern_entrypoint = True
        self.g17p_deferred_modern = True
        self.g17p_source_partial_integration = True
        return 0

    def modern_smoke_enable(self):
        """Select the corpus-backed render transport oracle for the C shim."""
        if self.initialized:
            return -errno.EBUSY
        self.g17p_render_transport_oracle = True
        return 0

    def _modern_call(self, label, callback):
        try:
            return callback()
        except KeyError as exc:
            self.log("%s: %s" % (label, exc))
            return -errno.ENOENT
        except (TypeError, ValueError) as exc:
            self.log("%s: %s" % (label, exc))
            return -errno.EINVAL
        except MemoryError as exc:
            self.log("%s: %s" % (label, exc))
            return -errno.ENOMEM
        except G17PUnsupported as exc:
            self.log("%s: %s" % (label, exc))
            return -errno.ENOSYS
        except RuntimeError as exc:
            self.log("%s: %s" % (label, exc))
            return -errno.EBUSY

    def modern_get_params(self, pointer, size):
        from .g17p_modern import VM_END, VM_KERNEL_MIN_SIZE, VM_START
        from .g17p_uapi import (
            DRM_ASAHI_FEATURE_SOFT_FAULTS,
            DRM_ASAHI_MAX_ATTACHMENTS,
            DRM_ASAHI_MAX_COMMANDS,
            drm_asahi_params_global,
        )

        params = drm_asahi_params_global()
        params.features = DRM_ASAHI_FEATURE_SOFT_FAULTS
        params.gpu_generation = 17
        params.gpu_variant = ord("P")
        params.gpu_revision = 0
        params.chip_id = 0x8140
        params.num_dies = 1
        params.num_clusters_total = 1
        params.num_cores_per_cluster = 6
        params.max_frequency_khz = 0
        params.core_masks[0] = 0x3d
        params.vm_start = VM_START
        params.vm_end = VM_END
        params.vm_kernel_min_size = VM_KERNEL_MIN_SIZE
        params.max_commands_per_submission = DRM_ASAHI_MAX_COMMANDS
        params.max_attachments = DRM_ASAHI_MAX_ATTACHMENTS
        params.command_timestamp_frequency_hz = 1_000_000_000
        data = params.to_bytes()
        ctypes.memmove(int(pointer), data, min(int(size), len(data)))
        return 0

    def modern_get_time(self):
        """Return the live architectural counter used by command timestamps."""
        if self.g17p_deferred_modern and not self.initialized:
            from m1n1.setup import u
            return int(u.mrs("CNTPCT_EL0"))
        return self._modern_call(
            "modern get time",
            lambda: (self.init(), int(self.g17p.u.mrs("CNTPCT_EL0")))[1])

    def modern_vm_create(self, fd, kernel_start, kernel_end):
        return self._modern_call(
            "modern VM create",
            lambda: self.modern.create_vm(
                fd, kernel_start, kernel_end).vm_id)

    def modern_vm_destroy(self, fd, vm_id):
        return self._modern_call(
            "modern VM destroy",
            lambda: (self.modern.destroy_vm(fd, vm_id), 0)[1])

    def modern_gem_created(self, fd, handle, memfd_offset, size, flags, vm_id):
        return self._modern_call(
            "modern GEM create",
            lambda: (self.modern.create_bo(
                fd, handle, memfd_offset, size, flags, vm_id), 0)[1])

    def modern_gem_closed(self, fd, handle):
        return self._modern_call(
            "modern GEM close",
            lambda: (self.modern.destroy_bo(fd, handle), 0)[1])

    def modern_vm_bind(self, fd, vm_id, operations, count, stride):
        from .g17p_uapi import drm_asahi_gem_bind_op

        def bind_all():
            minimum = ctypes.sizeof(drm_asahi_gem_bind_op)
            if int(stride) < minimum:
                raise ValueError("GEM bind stride is too small")
            for index in range(int(count)):
                address = int(operations) + index * int(stride)
                raw = bytes(self.read_buf(address, int(stride)))
                operation = drm_asahi_gem_bind_op.from_bytes(
                    raw, extensible=True)
                self.modern.bind(fd, vm_id, operation)
            return 0

        return self._modern_call("modern VM bind", bind_all)

    def modern_gem_bind_object(self, fd, operation):
        from .g17p_uapi import drm_asahi_gem_bind_object

        def bind_object():
            raw = bytes(self.read_buf(
                int(operation), ctypes.sizeof(drm_asahi_gem_bind_object)))
            parsed = drm_asahi_gem_bind_object.from_bytes(raw)
            self.modern.bind_object(fd, parsed)
            ctypes.memmove(int(operation), parsed.to_bytes(), len(raw))
            return 0

        return self._modern_call("modern GEM bind object", bind_object)

    def modern_queue_create(self, fd, vm_id, priority, usc_exec_base):
        return self._modern_call(
            "modern queue create",
            lambda: self.modern.create_queue(
                fd, vm_id, priority, usc_exec_base).queue_id)

    def modern_queue_destroy(self, fd, queue_id):
        return self._modern_call(
            "modern queue destroy",
            lambda: (self.modern.destroy_queue(fd, queue_id), 0)[1])

    def modern_submit(self, fd, queue_id, cmdbuf, cmdbuf_size,
                      syncs, in_sync_count, out_sync_count):
        from .g17p_uapi import drm_asahi_sync

        def submit():
            total = int(in_sync_count) + int(out_sync_count)
            stride = ctypes.sizeof(drm_asahi_sync)
            parsed = tuple(
                drm_asahi_sync.from_bytes(bytes(self.read_buf(
                    int(syncs) + index * stride, stride)))
                for index in range(total)
            )
            command_buffer = bytes(self.read_buf(
                int(cmdbuf), int(cmdbuf_size)))
            self.modern.submit(
                fd, queue_id, command_buffer,
                in_syncs=parsed[:int(in_sync_count)],
                out_syncs=parsed[int(in_sync_count):])
            return 0

        return self._modern_call("modern submit", submit)

    def read_buf(self, ptr, size):
        return ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ubyte * size))[0]

    def create_bo_from_memfd(self, drm_fd, memfd_offset=None, size=None, flags=None):
        """Allocate one GPU BO for the C drm-shim's existing memfd range."""
        import types

        if flags is None:
            # Compatibility with the original three-argument experiment API.
            drm_fd, memfd_offset, size, flags = 0, drm_fd, memfd_offset, size
        self.init()
        self.g17p_context_for_fd(drm_fd)
        args = types.SimpleNamespace(
            offset=int(memfd_offset), size=int(size), flags=int(flags))
        ret = self.create_bo(drm_fd, args)
        if ret:
            raise OSError(-ret, "G17P BO allocation failed")
        return args.offset

    def g17p_context_for_fd(self, fd):
        """Select the file-private VM for a stable DRM-file identity."""
        if self.g17p is None:
            return None
        key = int(fd)
        context = self.g17p_fd_contexts.get(key)
        if context is None:
            used = set(self.g17p_fd_contexts.values())
            context = self.g17p_next_context
            while context in used or context == 0:
                context += 1
            if context >= self.g17p.space.uat.NUM_CONTEXTS:
                raise G17PUnsupported("no free G17P hardware context slot")
            self.g17p_fd_contexts[key] = context
            self.g17p_next_context = context + 1
            self.log("G17P DRM file %d -> UAT context %d" % (key, context))
        self.g17p.activate_execution_context(context)
        self.ctx = self.g17p.ctx
        return context

    def destroy_g17p_context_for_fd(self, fd):
        """Release an idle DRM-file VM after all of its BOs are closed."""
        self.init()
        key = int(fd)
        context = self.g17p_fd_contexts.get(key)
        if context is None:
            return None
        live = [
            obj for obj in self.bos.values()
            if getattr(obj, "_drm_fd", None) == key
            and not getattr(obj, "_destroyed", False)
        ]
        if live:
            raise RuntimeError(
                "DRM file %d still owns %d live BO(s)" % (key, len(live)))
        released = self.g17p.release_execution_context_render_objects(context)
        tombstone = self.g17p.destroy_execution_context(context)
        del self.g17p_fd_contexts[key]
        self.log(
            "G17P DRM file %d released %d render object(s) and UAT context %d" %
            (key, released, context))
        return tombstone

    def submit_v3(self, fd, cmdbuf_ptr):
        """Submit the unstable-v3 Mesa command buffer through the G17P backend.

        The 2022 ``agx/next`` Mesa branch used this larger command-buffer shape,
        while the original Python drm-shim front end retained the preceding
        compact shape. The fields consumed by G17P are common to both.
        """
        import struct
        import types

        self.init()
        context_id = self.g17p_context_for_fd(fd)
        size = drm_asahi_cmdbuf_v3_t.sizeof()
        source = drm_asahi_cmdbuf_v3_t.parse(
            self.read_buf(int(cmdbuf_ptr), size))
        depth_clear = struct.unpack("<f", struct.pack(
            "<I", source.isp_bgobjdepth))[0]
        cmdbuf = types.SimpleNamespace(
            flags=source.flags,
            encoder_ptr=source.encoder_ptr,
            encoder_id=source.encoder_id,
            cmd_ta_id=source.cmd_ta_id,
            cmd_3d_id=source.cmd_3d_id,
            ds_flags=source.zls_ctrl,
            depth_buffer=source.depth_buffer_1,
            stencil_buffer=source.stencil_buffer_1,
            scissor_array=source.scissor_array,
            depth_bias_array=source.depth_bias_array,
            ppp_multisamplectl=source.ppp_multisamplectl,
            ppp_ctrl=source.ppp_ctrl,
            utile_width=source.utile_width,
            utile_height=source.utile_height,
            samples=source.samples,
            iogpu_unk_49=source.iogpu_unk_49,
            fb_width=source.fb_width,
            fb_height=source.fb_height,
            load_pipeline=source.load_pipeline,
            load_pipeline_bind=source.load_pipeline_bind,
            store_pipeline=source.store_pipeline,
            store_pipeline_bind=source.store_pipeline_bind,
            partial_reload_pipeline=source.partial_reload_pipeline,
            partial_reload_pipeline_bind=source.partial_reload_pipeline_bind,
            partial_store_pipeline=source.partial_store_pipeline,
            partial_store_pipeline_bind=source.partial_store_pipeline_bind,
            depth_clear_value=depth_clear,
            stencil_clear_value=source.isp_bgobjvals & 0xff,
            attachments=source.attachments,
            attachment_count=source.attachment_count,
        )

        encoder_override = os.getenv("G17P_ENCODER_OVERRIDE")
        if encoder_override:
            old_encoder = cmdbuf.encoder_ptr
            cmdbuf.encoder_ptr = int(encoder_override, 0)
            self.log("G17P encoder override: %#x -> %#x" %
                     (old_encoder, cmdbuf.encoder_ptr))

        for field in (
                "load_pipeline", "load_pipeline_bind",
                "store_pipeline", "store_pipeline_bind"):
            raw = os.getenv("G17P_%s_OVERRIDE" % field.upper())
            if raw:
                old_value = getattr(cmdbuf, field)
                new_value = int(raw, 0)
                setattr(cmdbuf, field, new_value)
                self.log("G17P %s override: %#x -> %#x" %
                         (field, old_value, new_value))

        self.g17p_install_code_image()
        self.g17p_install_pipeline_image()

        self.log(
            "G17P submit: %dx%d encoder=%#x scissor=%#x depth_bias=%#x "
            "load=(%#x,%#x) store=(%#x,%#x) attachments=%d" % (
                cmdbuf.fb_width, cmdbuf.fb_height, cmdbuf.encoder_ptr,
                cmdbuf.scissor_array, cmdbuf.depth_bias_array,
                cmdbuf.load_pipeline, cmdbuf.load_pipeline_bind,
                cmdbuf.store_pipeline, cmdbuf.store_pipeline_bind,
                cmdbuf.attachment_count))
        for index, attachment in enumerate(
                cmdbuf.attachments[:cmdbuf.attachment_count]):
            self.log(
                "G17P attachment %d: pointer=%#x size=%#x type=%#x" % (
                    index, attachment.pointer, attachment.size,
                    attachment.type))

        self.log("Pushing objects...")
        context_bos = [
            obj for obj in self.bos.values()
            if getattr(obj, "_drm_context", context_id) == context_id
        ]
        # A render target is written by the GPU and read back by the host; uploading it costs
        # its full size over debug USB on every submission and cannot affect the result, so a
        # caller allocating one per submission flags it. It stays in context_bos, because that
        # list is also what an attachment is matched against.
        pushable = [obj for obj in context_bos
                    if not getattr(obj, "_no_push", False)]
        for obj in pushable:
            obj.push(True)
        self.log("Push done")

        attachment_objs = []
        for attachment in cmdbuf.attachments[:cmdbuf.attachment_count]:
            matches = [obj for obj in context_bos
                       if obj._addr == attachment.pointer
                       and not getattr(obj, "_destroyed", False)]
            if len(matches) != 1:
                raise G17PUnsupported(
                    "G17P attachment %#x is not one live BO in context %d" % (
                        attachment.pointer, context_id))
            attachment_objs.append(matches[0])

        self.g17p.submit_drm(
            cmdbuf, attachment_objs, context_id=context_id,
            **self.g17p_supplied())

        if self.pull_buffers:
            self.log("Pulling buffers...")
            for obj in attachment_objs:
                obj.pull()
            self.log("Pull done")

        self.frame += 1
        return 0

    def g17p_install_pipeline_image(self):
        """Install an opt-in raw G17P BG/EOT program page for experiments."""
        self.g17p_install_image(
            "pipeline", "G17P_PIPELINE_IMAGE", "0x10001990000",
            "g17p_pipeline_image")

    def g17p_install_code_image(self):
        """Install the code page paired with an opt-in G17P program page."""
        self.g17p_install_image(
            "code", "G17P_CODE_IMAGE", "0x10000000000",
            "g17p_code_image")

    def g17p_install_image(self, label, env_name, default_address, state_name):
        """Install one opt-in image in the attached render address space."""
        import json

        path = os.getenv(env_name)
        if not path:
            return
        path = os.path.abspath(os.path.expanduser(path))
        address = int(os.getenv(env_name + "_ADDR", default_address), 0)
        uat = self.g17p.space.uat
        page_size = uat.PAGE_SIZE
        page = address & ~(page_size - 1)
        offset = address - page

        physical_name = env_name + "_PA"
        physical = os.getenv(physical_name)
        artifact = None
        artifact_extent = None
        if physical:
            physical = int(physical, 0)
        else:
            candidates = [self.g17p_boot_artifact_path()]
            for candidate in candidates:
                if candidate is None:
                    continue
                try:
                    with open(candidate) as handle:
                        extent = (json.load(handle).get("attach") or {}).get(
                            "render_extent") or {}
                    mapped = extent.get("%#x" % page)
                except (OSError, ValueError):
                    continue
                if mapped is not None:
                    artifact = candidate
                    artifact_extent = extent
                    physical = int(mapped, 0) + offset

        context = int(os.getenv(
            env_name + "_CONTEXT", str(self.g17p.space.context)), 0)
        identity = (path, physical, context, address)
        if getattr(self, state_name) == identity:
            return
        with open(path, "rb") as handle:
            data = handle.read()
        max_image_size = 0x10000
        if not data or len(data) > max_image_size:
            raise G17PUnsupported(
                "G17P %s image must contain 1..%#x bytes; got %#x" %
                (label, max_image_size, len(data)))
        if address & 3:
            raise G17PUnsupported(
                "G17P %s image address must be 32-bit aligned; got %#x" %
                (label, address))
        if physical is not None:
            if artifact_extent is None:
                ranges = [(physical, len(data))]
            else:
                ranges = []
                written = 0
                while written < len(data):
                    current = address + written
                    current_page = current & ~(page_size - 1)
                    current_offset = current - current_page
                    mapped = artifact_extent.get("%#x" % current_page)
                    if mapped is None:
                        raise G17PUnsupported(
                            "G17P %s image crosses an unrecorded render page at %#x" %
                            (label, current_page))
                    length = min(page_size - current_offset,
                                 len(data) - written)
                    ranges.append((int(mapped, 0) + current_offset, length))
                    written += length
            written = 0
            for target, length in ranges:
                self.g17p.u.iface.writemem(
                    target, data[written:written + length])
                self.g17p.u.proxy.dc_civac(target, length)
                written += length
            readback = b"".join(
                bytes(self.g17p.u.iface.readmem(target, length))
                for target, length in ranges)
            destination = "physical %#x from %s" % (
                physical, artifact or physical_name)
        else:
            uat.iowrite(context, address, data)
            readback = uat.ioread(context, address, len(data))
            destination = "context %d:%#x" % (context, address)
        if readback != data:
            raise RuntimeError(
                "G17P %s image did not read back at %s" %
                (label, destination))
        setattr(self, state_name, identity)
        self.log("G17P %s image: %s -> %s (%#x bytes)" %
                 (label, path, destination, len(data)))

    # Chips whose GPU this front end serves through the G17P backend rather than the
    # earlier generations' one.
    G17P_CHIPS = (0x8140,)

    def init_agx(self):
        from m1n1.setup import p, u, iface

        chip = int(u.adt["/chosen"].chip_id)
        if chip in self.G17P_CHIPS:
            return self.init_agx_g17p(p, u)

        p.pmgr_adt_power_enable("/arm-io/gfx-asc")
        p.pmgr_adt_power_enable("/arm-io/sgx")

        self.agx = agx = AGX(u)

        mon = RegMonitor(u, ascii=True, bufsize=0x8000000)
        agx.mon = mon

        sgx = agx.sgx_dev
        #mon.add(sgx.gpu_region_base, sgx.gpu_region_size, "contexts")
        #mon.add(sgx.gfx_shared_region_base, sgx.gfx_shared_region_size, "gfx-shared")
        #mon.add(sgx.gfx_handoff_base, sgx.gfx_handoff_size, "gfx-handoff")

        #mon.add(agx.initdasgx.gfx_handoff_base, sgx.gfx_handoff_size, "gfx-handoff")

        atexit.register(p.reboot)
        agx.start()

    def init_agx_g17p(self, p, u):
        """Cold-boot G17P in-process when requested, or attach to an existing world."""
        for name, value in self.G17P_DEFAULTS.items():
            os.environ.setdefault(name, value)
        cold_boot = os.environ.get("G17P_COLD_BOOT") not in (None, "", "0")
        runtime = self.g17p_cold_boot() if cold_boot else None
        self.g17p_runtime = runtime
        if runtime is not None:
            attach = runtime["attach"]
            addr = attach["initdata_addr"]
            secondary_addr = attach.get("secondary_initdata_addr")
            context = int(attach.get("context", 1))
            self.g17p_render_extent = attach.get("render_extent") or {}
            self.g17p_submission_state = attach.get("submission_state")
            self.g17p_bound_submission = attach.get("bound_submission")
            self.g17p_boot_artifact = runtime.get("artifact")
            self.g17p_boot_runtime = runtime
        else:
            addr = os.environ.get("G17P_INITDATA_ADDR")
            secondary_addr = os.environ.get("G17P_SECONDARY_INITDATA_ADDR")
            if addr is None:
                addr = self.g17p_attach_from_artifact()
                secondary_addr = getattr(
                    self, "g17p_secondary_initdata_addr", secondary_addr)
            context = 1
        if addr is None:
            raise G17PUnsupported(
                "G17P_INITDATA_ADDR is unset and no boot artifact records an attach block: "
                "set G17P_COLD_BOOT=1 to start firmware in this DRM-shim process")

        direct_bootstrap = (runtime or {}).get("modern_direct_bootstrap")
        if direct_bootstrap is not None:
            self.g17p_direct_bootstrap = direct_bootstrap
            self.g17p = direct_bootstrap["backend"]
            # The direct compute bootstrap also constructs the render extent,
            # but its backend is created before that extent exists.  Retain the
            # finished source-built mappings so a later render can bind its
            # caller-owned targets without falling back to an artifact.
            self.g17p.retained_extent = {
                int(address, 0) if isinstance(address, str) else int(address):
                int(pa, 0) if isinstance(pa, str) else int(pa)
                for address, pa in self.g17p_render_extent.items()
            }
            self.g17p.bound_submission = dict(
                self.g17p_bound_submission or {})
            # The retained-render cold boot has a live render pair zero whose
            # graph pair one deliberately shares.  Direct compute has no render
            # pair zero, so its first render pair must own the graph it builds.
            self.g17p.share_bound_record_pools = False
            self.g17p.share_bound_submission_state = False
            self.g17p_asc = runtime["ascs"][0]
            self.g17p_doorbell = self.g17p_asc.db
            self.agx = None
            return self.g17p

        from m1n1.fw.asc import StandardASC
        from m1n1.fw.asc.base import ASCBaseEndpoint
        from m1n1.agx.g17p import MSG_WORK_DOORBELL
        from m1n1.utils import Register64

        class GpuMsg(Register64):
            TYPE = 55, 48
            CHANNEL = 47, 32

        class DoorbellEndpoint(ASCBaseEndpoint):
            BASE_MESSAGE = GpuMsg
            SHORT = "db"

        if runtime is None:
            self.g17p_asc = StandardASC(
                u, int(u.adt["/arm-io/gfx-asc"].get_reg(0)[0]))
            self.g17p_doorbell = DoorbellEndpoint(self.g17p_asc, 0x21)
            doorbell_message = GpuMsg
            control_message = GpuMsg
        else:
            self.g17p_asc = runtime["ascs"][0]
            self.g17p_doorbell = self.g17p_asc.db
            doorbell_message = runtime["doorbell_message"]
            control_message = runtime["control_message"]

        def doorbell(value=0):
            self.g17p_doorbell.send(
                doorbell_message(TYPE=MSG_WORK_DOORBELL, CHANNEL=value))

        def control_done():
            self.g17p_doorbell.send(control_message(0x0084000000000011))

        def pump_events():
            if runtime is None:
                return
            import time

            counts = []
            empty_rounds = 0
            for _ in range(16):
                moved = []
                for asc in runtime["ascs"]:
                    before = getattr(asc.fw, "events", 0)
                    # Do not drain to empty. Firmware can continuously emit 0x42 while a visible
                    # work producer is waiting for its doorbell, so an empty-mailbox barrier can
                    # prevent the host from ever sending that doorbell.
                    if asc.has_messages():
                        asc.work()
                    moved.append(getattr(asc.fw, "events", 0) - before)
                counts.append(tuple(moved))
                if any(moved):
                    empty_rounds = 0
                else:
                    empty_rounds += 1
                    if empty_rounds >= 2:
                        break
                time.sleep(0.001)
            print("G17P drained completion events after control-done: %s" % counts,
                  flush=True)

        self.g17p = G17PShimBackend(
            u, int(addr, 0) if isinstance(addr, str) else int(addr), doorbell,
            context=context, adopt=True,
            firmware_root="high", control_done=control_done,
            event_pump=pump_events,
            runtime_pair_register=(runtime or {}).get("register_runtime_pair"),
            runtime_submission_announce=(runtime or {}).get(
                "announce_runtime_submission"),
            retained_extent=getattr(self, "g17p_render_extent", None),
            bound_submission=getattr(self, "g17p_bound_submission", None),
            secondary_initdata_addr=(
                int(secondary_addr, 0)
                if isinstance(secondary_addr, str) else secondary_addr),
            firmware_high_root=(runtime or {}).get("firmware_high_root"))
        self.g17p.space.use_absent_handoff()
        self.agx = None
        return self.g17p

    def g17p_cold_boot(self):
        """Run the established cold bring-up in this embedded-Python process."""
        import importlib
        import importlib.util
        import pathlib

        if getattr(self, "g17p_source_partial_integration", False):
            experiments = pathlib.Path(__file__).resolve().parents[2] / "experiments"
            if str(experiments) not in sys.path:
                sys.path.insert(0, str(experiments))
            partial = importlib.import_module(
                "agx_g17p_render_uapi_partial_opening")
            self.log(
                "G17P: cold-publishing the source-built first-partial "
                "integration command")
            state = partial.main(
                return_state=True,
                integration_output_bo=self.g17p_partial_integration_output_bo,
            )
            self.log(
                "G17P: source-built first-partial integration complete (%s)" %
                state["artifact"])
            return state

        if (self.g17p_modern_entrypoint
                or os.environ.get("G17P_MODERN_DIRECT_BOOTSTRAP") == "1"):
            experiments = pathlib.Path(__file__).resolve().parents[2] / "experiments"
            if str(experiments) not in sys.path:
                sys.path.insert(0, str(experiments))
            source = importlib.import_module(
                "agx_g17p_compute_source_initial")
            self.log(
                "G17P: cold-booting a retained direct-compute lifetime")
            state = source.main(
                exact_client_context_table=True,
                alias_context0_queue=True,
                native_shader_attributes=True,
                repeat_workloads=1,
                firmware_item_capacity=258,
                client_workload_capacity=2,
                secondary_opening_only=True,
                post_start_initial=True,
                native_control_tail=(
                    True if self.g17p_modern_entrypoint else
                    os.environ.get(
                        "G17P_MODERN_DIRECT_NATIVE_CONTROL_TAIL", "1")
                    != "0"),
                suppress_runtime_controls=True,
                drain_runtime_reports=True,
                drain_runtime_report_interval=1,
                return_state=True,
            )
            self.log(
                "G17P: direct-compute cold boot complete (%s)" %
                state["artifact"])
            return state

        path = (pathlib.Path(__file__).resolve().parents[2]
                / "experiments" / "agx_g17p_boot.py")
        name = "m1n1_g17p_drm_cold_boot"
        module = sys.modules.get(name)
        if module is None:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        self.log("G17P: cold-booting firmware inside DRM-shim")
        args = list(self.G17P_COLD_BOOT_ARGS)
        experimental_no_seed = os.environ.get("G17P_EXPERIMENT_NO_SEED")
        if experimental_no_seed is not None:
            index = args.index("--no-seed")
            del args[index:index + 2]
            args.remove("--require-zero-capture-pages")
            if experimental_no_seed != "none":
                args.extend(("--no-seed", experimental_no_seed))
            self.log(
                "G17P: EXPERIMENT enabling capture content; suppressed blocks=%s" %
                experimental_no_seed)
        if os.environ.get("G17P_EXPERIMENT_SEED_ATTACHMENTS") == "1":
            args.append("--seed-constructed-attachments")
            self.log("G17P: EXPERIMENT seeding the two constructed attachment pages")
        seed_attachment = os.environ.get("G17P_EXPERIMENT_SEED_ATTACHMENT")
        if seed_attachment:
            args.extend(("--seed-constructed-attachment", seed_attachment))
            self.log("G17P: EXPERIMENT seeding constructed attachment page %s" %
                     seed_attachment)
        seed_extra_except = os.environ.get("G17P_EXPERIMENT_SEED_EXTRA_EXCEPT")
        if seed_extra_except:
            args.extend(("--seed-extra-except", seed_extra_except))
            self.log("G17P: EXPERIMENT leaving render-extra ranges blank: %s" %
                     seed_extra_except)
        zero_render_bytes = os.environ.get("G17P_EXPERIMENT_ZERO_RENDER_BYTES")
        if zero_render_bytes:
            args.extend(("--zero-render-bytes", zero_render_bytes))
            self.log("G17P: EXPERIMENT zeroing render byte ranges: %s" %
                     zero_render_bytes)
        render_payload_manifest = os.environ.get(
            "G17P_EXPERIMENT_RENDER_PAYLOAD_MANIFEST")
        if render_payload_manifest is None:
            default_manifests = (
                pathlib.Path(__file__).resolve().parents[4]
                / "artifacts" / "agx_g17p" / "workload_payloads"
                / "reference_a18_render" / "manifest.json",
                pathlib.Path.home() / "asahi_re" / "artifacts" / "agx_g17p"
                / "workload_payloads" / "reference_a18_render"
                / "manifest.json",
            )
            default_manifest = next(
                (candidate for candidate in default_manifests
                 if candidate.is_file()), None)
            if default_manifest is not None:
                render_payload_manifest = str(default_manifest)
                self.log("G17P: using default caller payload manifest %s" %
                         render_payload_manifest)
        if render_payload_manifest:
            args.extend(("--render-payload-manifest", render_payload_manifest))
            self.log("G17P: EXPERIMENT loading caller payload manifest %s" %
                     render_payload_manifest)
        if os.environ.get("G17P_NATIVE_MAILBOX_ORDER") == "1":
            args.append("--native-mailbox-order")
        state = module.main(args, return_state=True)
        self.log("G17P: in-process cold boot complete (%s)" % state["artifact"])
        return state

    def g17p_state_from_artifact(self):
        """The submission state the newest boot artifact records, or None."""
        if getattr(self, "g17p_submission_state", None) is not None:
            return self.g17p_submission_state
        import json

        path = self.g17p_boot_artifact_path()
        if path is None:
            return None
        try:
            with open(path) as handle:
                attach = json.load(handle).get("attach") or {}
        except (OSError, ValueError):
            return None
        return attach.get("submission_state")

    def g17p_boot_artifact_path(self):
        """Return the explicitly selected boot artifact, or the newest local one."""
        import glob

        explicit = os.environ.get("G17P_BOOT_ARTIFACT")
        if explicit:
            path = os.path.abspath(os.path.expanduser(explicit))
            if os.path.isdir(path):
                path = os.path.join(path, "boot.json")
            return path
        root = os.environ.get(
            "G17P_ARTIFACTS",
            os.path.expanduser("~/asahi_re/artifacts/agx_g17p"))
        paths = sorted(glob.glob(os.path.join(root, "boot_*", "boot.json")))
        return paths[-1] if paths else None

    def g17p_attach_from_artifact(self):
        """The initdata address of the most recent boot, from its own artifact.

        The boot experiment knows the address it handed firmware and writes it into `boot.json`
        under `attach`. Reading it here means the two halves do not have to be connected by hand
        through an environment variable. Returns None when there is no artifact to read.
        """
        import json

        path = self.g17p_boot_artifact_path()
        if path is None:
            return None
        try:
            with open(path) as handle:
                attach = json.load(handle).get("attach")
        except (OSError, ValueError):
            return None
        if not attach or not attach.get("initdata_addr"):
            return None
        self.g17p_render_extent = attach.get("render_extent") or {}
        self.g17p_submission_state = attach.get("submission_state")
        self.g17p_bound_submission = attach.get("bound_submission")
        self.g17p_secondary_initdata_addr = attach.get(
            "secondary_initdata_addr")
        self.g17p_boot_artifact = path
        self.log("G17P: attaching to the firmware started by %s" % path)
        return "%#x" % int(attach["initdata_addr"])

    def g17p_supplied(self):
        """The submission state a DRM command buffer does not carry, from the environment.

        The register recipe names deflake and auxiliary-framebuffer addresses, and publication
        needs the shared record, the record pools and both optional records. None of those are in
        the DRM command buffer, and none are derivable here yet, so they are supplied as JSON
        rather than defaulted: a zero here publishes work that completes and draws nothing.

        ``G17P_SUBMISSION_STATE`` is either inline JSON or a path to a JSON file. Integers may be
        written as strings so hexadecimal addresses stay readable.
        """
        import json

        raw = os.environ.get("G17P_SUBMISSION_STATE")
        if raw is None:
            # The boot that started this firmware knows these and records them; prefer that to
            # making someone paste them.
            from_artifact = self.g17p_state_from_artifact()
            if from_artifact is not None:
                raw = json.dumps(from_artifact)
        if raw is None:
            raise G17PUnsupported(
                "G17P_SUBMISSION_STATE is unset: a DRM command buffer does not carry the "
                "deflake and auxiliary-framebuffer addresses, the shared record, the record "
                "pools or the optional records, and this backend does not derive them yet")
        if not raw.lstrip().startswith("{"):
            with open(raw) as state:
                supplied = json.load(state)
        else:
            supplied = json.loads(raw)

        def scalar(value):
            if isinstance(value, str):
                return int(value, 0)
            if isinstance(value, list):
                return [scalar(item) for item in value]
            if isinstance(value, dict):
                return {key: scalar(item) for key, item in value.items()}
            return value

        return {name: scalar(value) for name, value in supplied.items()}

    def init(self):
        if self.initialized:
            return

        backend = self.init_agx()
        if isinstance(backend, G17PShimBackend):
            # The G17P backend carries its own context and allocators; there is no renderer,
            # because turning a command buffer into work items is not decoded for this part.
            self.ctx = backend.ctx
            self.renderer = None
            if self.g17p_render_transport_oracle:
                import importlib
                import pathlib

                experiments = (pathlib.Path(__file__).resolve().parents[2]
                               / "experiments")
                if str(experiments) not in sys.path:
                    sys.path.insert(0, str(experiments))
                helper = importlib.import_module("agx_g17p_compute")
                self.log(
                    "G17P DRM TRANSPORT ORACLE: draining corpus-backed "
                    "opening render")
                helper.drain_boot_group(self, backend)
            self.initialized = True
            return

        self.ctx = GPUContext(self.agx)
        self.ctx.bind(0x17)
        self.renderer = GPURenderer(self.ctx, 0x40, bm_slot=10, queue=1)

        self.initialized = True

    @IOW(DRM_COMMAND_BASE + 0x00, drm_asahi_submit_t)
    def submit(self, fd, args):
        if self.renderer is None and self.g17p is None:
            self.log("submit: no backend on this chip")
            return -errno.ENOSYS

        sys.stdout.write(".")
        sys.stdout.flush()

        context_id = self.g17p_context_for_fd(fd)

        size = drm_asahi_cmdbuf_t.sizeof()
        cmdbuf = drm_asahi_cmdbuf_t.parse(self.read_buf(args.cmdbuf, size))

        self.log("Pushing objects...")
        context_bos = [
            obj for obj in self.bos.values()
            if getattr(obj, "_drm_context", context_id) == context_id
        ]
        # A render target is written by the GPU and read back by the host; uploading it costs
        # its full size over debug USB on every submission and cannot affect the result, so a
        # caller allocating one per submission flags it. It stays in context_bos, because that
        # list is also what an attachment is matched against.
        pushable = [obj for obj in context_bos
                    if not getattr(obj, "_no_push", False)]
        for obj in pushable:
            #if obj._skipped_pushes > 64:# and obj._addr > 0x1200000000 and obj._size > 131072:
                #continue
            obj.push(True)
        self.log("Push done")

        attachment_objs = []
        for attachment in cmdbuf.attachments[:cmdbuf.attachment_count]:
            matches = [obj for obj in context_bos
                       if obj._addr == attachment.pointer
                       and not getattr(obj, "_destroyed", False)]
            if len(matches) != 1:
                raise G17PUnsupported(
                    "G17P attachment %#x is not one live BO in context %d" % (
                        attachment.pointer, context_id))
            attachment_objs.append(matches[0])

        if self.dump_frames and self.renderer is not None:
            name = f"shim_frame{self.frame:03d}.agx"
            f = GPUFrame(self.renderer.ctx)
            f.cmdbuf = cmdbuf
            for obj in self.bos.values():
                f.add_object(obj)
            f.save(name)

        if self.renderer is None:
            # G17P publishes a paired submission and its own completion records; there is no
            # separate run/wait step. What the DRM buffer does not carry has to come from the
            # environment, and submit_drm refuses by name for anything still missing.
            self.g17p.submit_drm(
                cmdbuf, attachment_objs, context_id=context_id,
                **self.g17p_supplied())
        else:
            self.renderer.submit(cmdbuf)
            self.renderer.run()
            self.renderer.wait()

        if self.pull_buffers:
            self.log("Pulling buffers...")
            for obj in attachment_objs:
                obj.pull()
                obj._map[:] = obj.val
                obj.val = obj._map
            self.log("Pull done")

        #print("HEAP STATS")
        #self.ctx.uobj.va.check()
        #self.ctx.gobj.va.check()
        #self.ctx.pobj.va.check()
        #self.agx.kobj.va.check()
        #self.agx.cmdbuf.va.check()
        #self.agx.kshared.va.check()
        #self.agx.kshared2.va.check()

        self.frame += 1
        return 0

    @IOW(DRM_COMMAND_BASE + 0x01, drm_asahi_wait_bo_t)
    def wait_bo(self, fd, args):
        self.log("Wait BO!", args)
        return 0

    @IOWR(DRM_COMMAND_BASE + 0x02, drm_asahi_create_bo_t)
    def create_bo(self, fd, args):
        memfd_offset = args.offset

        context_id = self.g17p_context_for_fd(fd)
        context = self.ctx if self.renderer is None else self.renderer.ctx
        if args.flags & ASAHI_BO_PIPELINE:
            alloc = context.pobj
        else:
            alloc = context.gobj

        try:
            obj = alloc.new(
                args.size, name=f"GBM offset {memfd_offset:#x}", track=False)
        except MemoryError as exc:
            self.log("Create BO failed: %s" % exc)
            return -errno.ENOMEM
        obj._memfd_offset = memfd_offset
        obj._drm_context = context_id
        obj._drm_fd = int(fd)
        obj._pushed = False
        obj.val = obj._map = mmap.mmap(self.memfd, args.size, offset=memfd_offset)
        self.bos[memfd_offset] = obj
        args.offset = obj._addr

        if args.flags & ASAHI_BO_PIPELINE:
            args.offset -= context.pipeline_base

        self.log(
            "Create BO: memfd=%#x gpu=%#x size=%#x flags=%#x" % (
                memfd_offset, obj._addr, args.size, args.flags))
        return 0

    @IOWR(DRM_COMMAND_BASE + 0x04, drm_asahi_get_param_t)
    def get_param(self, fd, args):
        self.log("Get Param!", args)
        return 0

    @IOWR(DRM_COMMAND_BASE + 0x05, drm_asahi_get_bo_offset_t)
    def get_bo_offset(self, fd, args):
        self.log("Get BO Offset!", args)
        return 0

    def bo_free(self, memfd_offset):
        self.log(f"Free BO @ {memfd_offset:#x}")
        self.bos[memfd_offset].free()
        del self.bos[memfd_offset]
        sys.stdout.flush()

    def ioctl(self, fd, request, p_arg):
        self.init()

        p_arg = ctypes.c_void_p(p_arg)

        if request not in self.ioctl_map:
            self.log(f"Unknown ioctl: fd={fd} request={IOCTL(request)} arg={p_arg:#x}")
            return -errno.ENOSYS

        ioctl, f = self.ioctl_map[request]

        size = ioctl.SIZE
        if ioctl.DIR & _IOC_WRITE:
            args = f._arg_cls.parse(self.read_buf(p_arg, size))
            ret = f(fd, args)
        elif ioctl.DIR & _IOC_READ:
            args = f._arg_cls.parse(bytes(size))
            ret = f(fd, args)
        else:
            ret = f(fd)

        if ioctl.DIR & _IOC_READ:
            data = args.build()
            assert len(data) == size
            ctypes.memmove(p_arg, data, size)

        sys.stdout.flush()
        return ret

    def log(self, s):
        if self.agx is None:
            print("[Shim] " + s, flush=True)
        else:
            self.agx.log("[Shim] " + s)

Shim = DRMAsahiShim
