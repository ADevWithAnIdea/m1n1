# SPDX-License-Identifier: MIT
"""Compare the coldboot's initdata root and main config against a working snapshot's.

Firmware acknowledges the coldboot's initdata and then services nothing, while the same firmware
booted against a restored world services channels. Both are fresh firmware boots, so the difference
is in what they read, and the root is the first thing they read.

Pointers must differ, since the two worlds place their objects differently. Scalars should not, and
a scalar that differs, or a field set in one and zero in the other, is a candidate for what tells
firmware whether to run.

The coldboot's values are pasted from its --dump-state output rather than read live, so this needs
no hardware.
"""
import json
import pathlib
import struct

PAGE = 0x4000
SNAP = "/Users/user/asahi_re/artifacts/agx_g17p/pre_work_0x83_v2_20260724_193713"
FW_TAG = 0xFFFFFC20

# From the coldboot run with --full-control --native-kick --dump-state.
COLDBOOT_ROOT = {
    0x00: 0x0C8AA322039604C0,
    0x08: 0xFFFFFC201002C000,
    0x18: 0xFFFFFC2010034000,
    0x20: 0xFFFFFC2010030000,
    0x28: 0x0000000100000000,
    0x30: 0x240E0E08030E4000,
    0x38: 0x0000000140000040,
    0x40: 0xFFFFC00000000000,
    0x48: 0x00000000000003FF,
    0x50: 0x190E0E08000003F0,
    0x58: 0x0000000140000800,
    0x60: 0xFFFFC00000000000,
}
COLDBOOT_MAIN = {
    0x00: 0xFFFFFC2010000000,
    0x08: 0xFFFFFC201000C500,
    0x10: 0xFFFFFC201000C500,
    0x20: 0xFFFFFC2010040000,
    0x28: 0xFFFFFC2010040010,
    0x30: 0xFFFFFC2010040020,
    0x38: 0xFFFFFC2010044000,
}


class Snapshot:
    def __init__(self, directory):
        self.dir = pathlib.Path(directory)
        self.manifest = json.load(open(self.dir / "manifest.json"))
        self.ram = open(self.dir / "ram.bin", "rb")
        self.pages = {}
        for group in self.manifest["root_mappings"]:
            if group.get("root_ctx_id") != 64 or group.get("selector") != 1:
                continue
            for mapping in group["mappings"]:
                if mapping.get("blob_index") is None:
                    continue
                self.pages[int(mapping["va"]) & ~(PAGE - 1)] = int(mapping["blob_index"])

    def read(self, dva, size):
        out = bytearray()
        while size:
            page = dva & ~(PAGE - 1)
            index = self.pages.get(page)
            if index is None:
                return None
            offset = dva & (PAGE - 1)
            take = min(size, PAGE - offset)
            self.ram.seek(index * PAGE + offset)
            out += self.ram.read(take)
            dva += take
            size -= take
        return bytes(out)

    def u64(self, dva):
        raw = self.read(dva, 8)
        return None if raw is None else struct.unpack("<Q", raw)[0]


snap = Snapshot(SNAP)
init = int(snap.manifest["init_addr"])
print("snapshot init_addr %#x" % init)


def is_pointer(value):
    return value is not None and (value >> 32) == FW_TAG


def compare(name, native_base, coldboot):
    print("\n%s: snapshot at %#x" % (name, native_base))
    offsets = sorted(set(coldboot) | set(range(0, 0x68, 8)))
    for off in offsets:
        native = snap.u64(native_base + off)
        cold = coldboot.get(off, 0)
        if native is None:
            continue
        if native == cold:
            continue
        kind = ""
        if is_pointer(native) and is_pointer(cold):
            kind = "  both pointers, differ by construction"
        elif is_pointer(native) != is_pointer(cold):
            kind = "  *** one is a pointer and the other is not ***"
        elif native and not cold:
            kind = "  *** set natively, zero in the coldboot ***"
        elif cold and not native:
            kind = "  *** set in the coldboot, zero natively ***"
        else:
            kind = "  *** scalars differ ***"
        print("   +%#04x  native %#018x  coldboot %#018x%s" % (off, native, cold, kind))


compare("initdata root", init, COLDBOOT_ROOT)

# The region is an array of channel descriptors, 0x20 bytes each: three state pointers and a
# ring. Device control sits at +0x1a0, which is group twelve, after the twelve work channels.
native_region = snap.u64(init + 0x18)
print()
print('native channel descriptor array in the region at root+0x18:')
for group in range(14):
    base = native_region + 0x20 + group * 0x20
    words = [snap.u64(base + off) for off in (0, 8, 0x10, 0x18)]
    if all(w in (None, 0) for w in words):
        print('   group %2d (+%#05x)  all zero' % (group, 0x20 + group * 0x20))
        continue
    print('   group %2d (+%#05x)  %s' % (group, 0x20 + group * 0x20,
          ' '.join('%#x' % (w or 0) for w in words)))
print()
print('device control is at region+0x1a0, which is group %d' % ((0x1a0 - 0x20) // 0x20))

native_main = snap.u64(init + 0x18)
if False:
    # main_config on the coldboot side is what its dump calls main_config; natively it is
    # reached the same way the channel table is, through the root's second region.
    compare("region at root+0x18", native_main, COLDBOOT_MAIN)
