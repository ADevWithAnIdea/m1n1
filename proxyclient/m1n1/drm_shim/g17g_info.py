# SPDX-License-Identifier: GPL-2.0-only
"""T8142 live device properties from ADT and hardware ID registers.

The ID fields/core mask and 1 GHz architectural clock were observed in
device_info_20260911. Keep the G17G identity/geometry gates explicit: importing
this decoder must never quietly select an older GPU's guessed topology.
"""
import errno

from .g17g_modern import VM_START, VM_END, VM_KERNEL_MIN_SIZE
from .g17g_uapi import (
    drm_asahi_params_global, DRM_ASAHI_FEATURE_SOFT_FAULTS,
    DRM_ASAHI_MAX_COMMANDS, DRM_ASAHI_MAX_ATTACHMENTS,
)


def decode_params(chip_id, version, counts, masks, frequencies, counter_hz):
    if chip_id != 0x8142 or version >> 24 != 0xb or (version >> 16) & 0xff != 2:
        raise OSError(errno.ENODEV, "unqualified G17G GPU identity")
    cores, clusters_per_die, dies = counts & 0xff, (counts >> 8) & 0xff, (counts >> 16) & 0xf
    clusters = dies * clusters_per_die
    if dies != 1 or clusters != 1 or cores != 10:
        raise OSError(errno.ENODEV, "unqualified G17G core geometry")
    revision = (version >> 8) & 0xff
    if revision != 0x20:
        raise OSError(errno.ENODEV, "unqualified T8142 GPU revision")
    packed = sum(int(mask) << (32 * index) for index, mask in enumerate(masks))
    if not packed or packed >> (cores * clusters):
        raise OSError(errno.EIO, "GPU core mask exceeds reported geometry")
    frequencies = tuple(int(value) for value in frequencies)
    if not frequencies or any(value < 0 for value in frequencies) or max(frequencies) <= 0:
        raise OSError(errno.EIO, "ADT lacks a valid GPU frequency table")
    if counter_hz != 1_000_000_000:
        raise OSError(errno.ENODEV, "unqualified T8142 timestamp clock")
    params = drm_asahi_params_global()
    params.features = DRM_ASAHI_FEATURE_SOFT_FAULTS
    params.gpu_generation, params.gpu_variant = 17, ord("G")
    params.gpu_revision, params.chip_id = revision, chip_id
    params.num_dies, params.num_clusters_total = dies, clusters
    params.num_cores_per_cluster = cores
    params.max_frequency_khz = max(frequencies) // 1000
    for index in range(clusters):
        params.core_masks[index] = (packed >> (index * cores)) & ((1 << cores) - 1)
    params.vm_start, params.vm_end = VM_START, VM_END
    params.vm_kernel_min_size = VM_KERNEL_MIN_SIZE
    params.max_commands_per_submission = DRM_ASAHI_MAX_COMMANDS
    params.max_attachments = DRM_ASAHI_MAX_ATTACHMENTS
    params.command_timestamp_frequency_hz = 1_000_000_000
    return params


class G17GDeviceInfo:
    def __init__(self, util):
        self.u = util
        self.params = None
        self.evidence = {}

    def discover(self):
        chip_id = int(self.u.adt["/chosen"].chip_id)
        if chip_id != 0x8142:
            raise OSError(errno.ENODEV, "GPU discovery requires live T8142")
        sgx = self.u.adt["/arm-io/sgx"]
        base, size = sgx.get_reg(0)
        def read(offset):
            if offset + 4 > size:
                raise OSError(errno.EIO, "GPU ID register exceeds ADT range")
            self.u.proxy.get_exc_count()
            value = self.u.proxy.read32(base + offset)
            if self.u.proxy.get_exc_count():
                raise OSError(errno.EIO, "GPU identification read faulted")
            self.evidence[hex(offset)] = int(value)
            return int(value)
        version, counts = read(0xd04000), read(0xd04010)
        masks = tuple(read(0xe01500 + index * 4) for index in range(3))
        frequencies = tuple(int(state.freq) for state in sgx.perf_states)
        counter_hz = int(self.u.mrs("CNTFRQ_EL0"))
        self.params = decode_params(chip_id, version, counts, masks, frequencies, counter_hz)
        self.counter_hz = counter_hz
        self.evidence.update(counter_hz=counter_hz, frequencies=frequencies)
        return self.params.to_bytes()

    def get_params(self):
        return self.discover() if self.params is None else self.params.to_bytes()

    def get_time(self):
        if self.params is None:
            self.discover()
        # The unchanged UAPI returns nanoseconds, not generic counter ticks.
        return int(self.u.mrs("CNTPCT_EL0")) * 1_000_000_000 // self.counter_hz
