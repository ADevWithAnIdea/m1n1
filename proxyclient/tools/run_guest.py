#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import struct, sys, pathlib, traceback
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

import argparse, pathlib
from io import BytesIO

def volumespec(s):
    return tuple(s.split(":", 2))


def sptm_hv_boot_args(extra=()):
    def boot_arg_key(arg):
        return arg.split("=", 1)[0]

    words = list(extra)
    defaults = [
        "-nobsdmgroot",          # dodges a panic we otherwise hit on this boot path
        "wdt=-1",                # disables some internal XNU watchdog
        "sprr_tpro=0",           # disable XNU's TPRO boot policy; the commpage bit is patched separately
        "sprr_tpro_pagers=0",    # ... same, for pager mappings
        "-v",                    # Optional: verbose boot
        f"msgbuf={1024 * 1024}", # Optional: enlarge the kernel msgbuf
    ]
    for arg in defaults:
        key = boot_arg_key(arg)
        if not any(boot_arg_key(w) == key for w in words):
            words.append(arg)
    return " ".join(words)


def load_ramdisk(hv, path, *, min_offset=0, chunk_size=32 * 1024 * 1024):
    """Stage a raw XNU RAMDisk and publish its physical range in the guest ADT."""
    size = path.stat().st_size
    if not size:
        raise ValueError(f"RAMDisk is empty: {path}")

    page_size = 0x4000
    base = align(max(hv.tba.top_of_kernel_data,
                     hv.guest_base + min_offset), page_size)
    end = base + size
    mem_top = hv.u.ba.phys_base + hv.u.ba.mem_size
    if end > mem_top:
        raise ValueError(
            f"RAMDisk does not fit in guest RAM: 0x{base:x}..0x{end:x} "
            f"> 0x{mem_top:x}")

    print(
        f"Loading RAMDisk (0x{size:x} bytes) at 0x{base:x} "
        f"in 0x{chunk_size:x}-byte chunks...")
    offset = 0
    with path.open("rb") as fd:
        while True:
            chunk = fd.read(chunk_size)
            if not chunk:
                break
            print(
                f"  RAMDisk chunk 0x{offset:x}.."
                f"0x{offset + len(chunk):x}")
            hv.u.compressed_writemem(base + offset, chunk, True)
            offset += len(chunk)
    if offset != size:
        raise RuntimeError(
            f"short RAMDisk upload: 0x{offset:x} != 0x{size:x}")

    hv.p.dc_civac(base, size)

    probe_size = min(size, 64)
    with path.open("rb") as fd:
        first = fd.read(probe_size)
        fd.seek(size - probe_size)
        last = fd.read(probe_size)
    if hv.iface.readmem(base, probe_size) != first:
        raise RuntimeError("RAMDisk leading-edge readback mismatch")
    if hv.iface.readmem(end - probe_size, probe_size) != last:
        raise RuntimeError("RAMDisk trailing-edge readback mismatch")

    mmap = hv.adt["chosen"]["memory-map"]
    mmap._types.pop("RAMDisk", None)
    mmap._properties["RAMDisk"] = struct.pack("<QQ", base, size)
    hv.tba.top_of_kernel_data = align(end, page_size)
    hv.ramdisk_base = base
    hv.ramdisk_size = size
    hv.ramdisk_path = path
    print(
        f"RAMDisk staged and verified: /chosen/memory-map/RAMDisk="
        f"(0x{base:x}, 0x{size:x}), top_of_kernel_data="
        f"0x{hv.tba.top_of_kernel_data:x}")

parser = argparse.ArgumentParser(description='Run a Mach-O payload under the hypervisor')
parser.add_argument('-s', '--symbols', type=pathlib.Path)
parser.add_argument('-m', '--script', type=pathlib.Path, action='append', default=[])
parser.add_argument('-c', '--command', action="append", default=[])
parser.add_argument('-S', '--shell', action="store_true")
parser.add_argument('-e', '--hook-exceptions', action="store_true")
parser.add_argument('-d', '--debug-xnu', action="store_true")
parser.add_argument('-l', '--logfile', type=pathlib.Path)
parser.add_argument(
    '--headless-guest', action='store_true',
    help='Remove the internal display pipeline from a T8140 macOS guest',
)
parser.add_argument('-C', '--cpus', default=None)
parser.add_argument('--strip-node', action="append", default=[], metavar='SUBSTR',
                    help='Remove every ADT node whose name contains SUBSTR.')
parser.add_argument('-r', '--raw', action="store_true")
parser.add_argument('-E', '--entry-point', action="store", type=int, help="Entry point for the raw image", default=0x800)
parser.add_argument('-a', '--append-payload', type=pathlib.Path, action="append", default=[])
parser.add_argument('--ramdisk', type=pathlib.Path,
                    help='Stage a raw ramdisk and add /chosen/memory-map/RAMDisk')
parser.add_argument('-v', '--volume', type=volumespec, action='append',
                    help='Attach a 9P virtio device for file export to the guest. The argument is a host path to the '
                         'exported tree, joined by colon (\':\') with a tag under which the tree will be advertised '
                         'on the guest side.')
parser.add_argument('payload', type=pathlib.Path)
parser.add_argument('boot_args', default=[], nargs="*")
args = parser.parse_args()

from m1n1.proxy import *
from m1n1.proxyutils import *
from m1n1.utils import *
from m1n1.shell import run_shell
from m1n1.sysreg import *
from m1n1.hv import HV
from m1n1.hv.virtio import Virtio9PTransport
from m1n1.hw.pmu import PMU

iface = UartInterface()
p = M1N1Proxy(iface, debug=False)
bootstrap_port(iface, p)
u = ProxyUtils(p, heap_size = 128 * 1024 * 1024)

# Setup counter redirect / AHCR_EL2 as expected by macOS for macho payloads
if not args.raw:
    chip_id = u.adt["/chosen"].chip_id
    if chip_id in (0x6030, 0x6031, 0x6032, 0x6034, 0x8122):
        u.msr(AGTCNTRDIR_EL1, 3)
        u.msr(AGTCNTRDIR_EL12, 3)

hv = HV(iface, p, u)

hv.hook_exceptions = args.hook_exceptions

hv.init()

if args.cpus:
    avail = [i.name for i in hv.adt["/cpus"]]
    want = set(f"cpu{i}" for i in args.cpus)
    for cpu in avail:
        if cpu in want:
            continue
        try:
            del hv.adt[f"/cpus/{cpu}"]
            print(f"Disabled {cpu}")
        except KeyError:
            continue

if args.strip_node:
    def strip_nodes(node, path=""):
        for child in list(node):
            child_path = f"{path}/{child.name}"
            if any(pat.lower() in child.name.lower() for pat in args.strip_node):
                print(f"Removing ADT node {child_path}")
                del node[child.name]
            else:
                strip_nodes(child, child_path)

    strip_nodes(hv.adt)

if args.debug_xnu:
    hv.adt["chosen"].debug_enabled = 1

# Exclaves are not yet supported
if not args.raw and u.adt["/chosen"].chip_id in (0x8132, 0x8140, 0x6040, 0x6041):
    for name in ("/arm-io/exdisplaypipe", "/arm-io/exdisplaypipe-s-proxy",
                 "/arm-io/dcp-exclave-ioreporting", "/arm-io/dcp-exclave-mailbox"):
        try:
            del hv.adt[name]
        except KeyError:
            pass
    # The internal DCP's iop-dcp-nub binds its RTKit transport to the (now-gone)
    # dcp-exclave-mailbox via routes=206; clearing routes makes the DCP firmware
    # fall back to the plain ASC mailbox like the routeless external dcpext.
    try:
        nub = hv.adt["/arm-io/dcp/iop-dcp-nub"]
        if getattr(nub, "routes", None) is not None:
            del nub.routes
    except KeyError:
        pass

if args.headless_guest:
    if args.raw:
        parser.error('--headless-guest requires a Mach-O macOS guest')
    if u.adt["/chosen"].chip_id != 0x8140:
        parser.error('--headless-guest is currently scoped to T8140')

    # Experiment-only: leave AGX and its UAT intact while preventing the
    # internal display stack from creating render traffic.
    headless_nodes = (
        "/arm-io/displaymanager",
        "/arm-io/display-crossbar0",
        "/arm-io/disp0",
        "/arm-io/dcp0-expert",
        "/arm-io/dcp",
        "/arm-io/dart-dcp",
        "/arm-io/dart-disp0",
        "/arm-io/dart-dispgrt",
        "/arm-io/dcp-sac-controller",
        "/arm-io/admac-disp0",
        "/arm-io/admac-disp0-ced-ssw",
    )
    removed = []
    for path in headless_nodes:
        try:
            del hv.adt[path]
            removed.append(path)
        except KeyError:
            pass
    print("T8140 headless guest ADT: removed " + ", ".join(removed))

if args.volume:
    for path, tag in args.volume:
        hv.attach_virtio(Virtio9PTransport(root=path, tag=tag))

if args.logfile:
    hv.set_logfile(args.logfile.open("w"))

# macOS-under-HV needs a specific boot-arg set on the M4/macOS chip_ids
if not args.raw and u.adt["/chosen"].chip_id in (0x8132, 0x8140, 0x6040, 0x6041):
    hv.set_bootargs(sptm_hv_boot_args(args.boot_args))
elif len(args.boot_args) > 0:
    boot_args = " ".join(args.boot_args)
    hv.set_bootargs(boot_args)

symfile = None
if args.symbols:
    symfile = args.symbols.open("rb")

payload = args.payload.open("rb")

if args.append_payload:
    concat = BytesIO()
    concat.write(payload.read())
    for part in args.append_payload:
        concat.write(part.open("rb").read())
    concat.seek(0)
    payload = concat

if args.raw:
    hv.load_raw(payload.read(), args.entry_point)
else:
    hv.load_macho(payload, symfile=symfile)

if args.ramdisk:
    # The M4/A18 guest layout reserves fixed page-table and auxiliary regions
    # below guest_base + 256 MiB. Keep the RAMDisk above those ranges.
    ramdisk_min_offset = 0
    if not args.raw and u.adt["/chosen"].chip_id in (0x8132, 0x8140, 0x6040, 0x6041):
        ramdisk_min_offset = 0x10000000
    load_ramdisk(hv, args.ramdisk, min_offset=ramdisk_min_offset)

PMU(u).reset_panic_counter()

for i in args.script:
    try:
        hv.run_script(i)
    except:
        traceback.print_exc()
        args.shell = True

for i in args.command:
    try:
        hv.run_code(i)
    except:
        traceback.print_exc()
        args.shell = True

if args.shell:
    run_shell(hv.shell_locals, "Entering hypervisor shell. Type ^D to start the guest.")

hv.start()

run_shell(hv.shell_locals, "Hypervisor exited. Entering shell.")

p.smp_stop_secondaries(True)
p.sleep(True)
