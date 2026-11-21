# SPDX-License-Identifier: GPL-2.0-only
"""Per-VM ownership of resident private roots and their address arena."""
import struct


def descriptor_context(body, slot):
    if not 1 <= slot < 64:
        raise ValueError('invalid resident GPU context slot')
    data = bytearray(body)
    kind = struct.unpack_from('<I', data)[0]
    if kind == 3:
        from . import g17g_compute as compute
        start, count, fields = compute.COMPUTE_REGISTER_START, compute.COMPUTE_REGISTER_COUNT, {0x10201, 0x10428}
    elif kind == 0 and len(body) == 0x9c0:
        start, count, fields = 0x3cc, 9, {0x10209, 0x1c9f0, 0x14320}
    elif kind == 1 and len(body) == 0x2240:
        start, count, fields = 0xa0, 89, {0x10211, 0x10420}
    else:
        return body
    struct.pack_into('<I', data, 0xc, slot)
    for offset in range(start, start+count*12, 12):
        number, value = struct.unpack_from('<IQ', data, offset)
        if number in fields:
            struct.pack_into('<Q', data, offset+4, (slot << 8) | (value & 255))
    return bytes(data)


class G17GComputeContext:
    def __init__(self, runtime, vm, slot=1):
        self.runtime, self.vm = runtime, vm
        self.slot = slot
        from .g17g_vm_layout import G17GVMLayout
        self.layout = G17GVMLayout(vm.kernel_start, vm.kernel_end)
        self.record = None
        self.destroyed = False
        self.tombstone = None

    def assert_live(self):
        if self.destroyed or (self.record is not None and self.record.get("destroyed")):
            raise RuntimeError("cannot activate a destroyed compute VM")

    def unmap_binding(self, binding):
        return self.unmap_bindings((binding,))

    def unmap_bindings(self, bindings):
        self.assert_live()
        if self.record is None:
            raise RuntimeError("compute VM has no installed private roots")
        return self.runtime.unmap_bindings(bindings, context=self.record)

    def destroy(self):
        if self.tombstone is not None:
            return dict(self.tombstone)
        self.tombstone = (dict(never_activated=True, released=True) if self.record is None
                          else self.runtime.destroy_context(self.record))
        self.destroyed = True
        return dict(self.tombstone)
