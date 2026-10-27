#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the real Linux G17P Neo probe with hardware GPU passthrough and VUART.

Linux uses spin-table release words; the monitor retains the VUART console. GPU registers,
mailbox IRQs, firmware and RAM are never emulated. This is monitored Linux
bring-up; final bare-metal and native DRM output validation remain separate.
"""
import argparse
import ctypes as C
import json
import hashlib
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import threading

DEVICE = '/dev/cu.usbmodemGWXJTJCN2M1'
VUART = '/dev/cu.usbmodemGWXJTJCN2M3'
if os.environ.get('M1N1DEVICE') != DEVICE:
    raise SystemExit('Select the verified Neo explicitly with M1N1DEVICE=' + DEVICE)
root = Path.cwd()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('image', type=Path)
parser.add_argument('dtb', type=Path, help='6-CPU J700 spin-table DTB compiled with M1N1_MONITOR')
parser.add_argument('initramfs', type=Path)
parser.add_argument('--evidence', type=Path, required=True)
parser.add_argument('--enable-gpu', action='store_true')
parser.add_argument('--bootarg', action='append', default=[], help='one opt-in asahi_neo module parameter; all6 CPU settings stay fixed')
args = parser.parse_args()
import re
assert all(re.fullmatch(r"asahi_neo\.[a-z0-9_]+=(?:0x[0-9a-f]+|[0-9]+)", token) for token in args.bootarg), "Only numeric asahi_neo module parameters are accepted"
args.evidence.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(root/'proxyclient'))
sys.path.insert(0, str(root.parent/'linux-g16c-g17p/drivers/gpu/drm/asahi/tests'))
from host_fdt import Loader
from m1n1.asm import ARMAsm, BaseAsm
from m1n1.proxyutils import ProxyUtils
# Never automatically disassemble on exceptions, including monitor faults.
BaseAsm.objdump = lambda *a, **kw: None
BaseAsm.disassemble = lambda *a, **kw: iter(('[disassembly disabled]',))
ProxyUtils.disassemble_at = BaseAsm.objdump
from m1n1.setup import iface, p, u
from m1n1.hv import HV
from m1n1.sysreg import MPIDR_EL1, SCTLR_EL12
from m1n1.trace import TraceMode
from m1n1.utils import irange
import serial

assert iface.devpath == DEVICE
assert u.adt.model == 'Mac17,5' and p.get_chipid() == 0x8140
iface.tty_log = (args.evidence/'monitor.log').open('w')
iface.nop()
for name,expected in [('uart0',0x385200000),('aic',0x301000000),('sgx',0x480000000),('gfx-asc',0x482600000),('gfx1-asc',0x482e00000)]:
    assert u.adt['/arm-io/'+name].get_reg(0)[0] == expected, name
print('NEO_CPU_FEATURES',u.cpu_features,flush=True)
p.smp_start_secondaries()
mpidrs = [0,1,2,3,0x10100,0x10101]
boot_mpidr = u.mrs(MPIDR_EL1) & 0xffffff
boot_cpu = mpidrs.index(boot_mpidr)
assert all(i == boot_cpu or p.smp_is_alive(i) for i in range(6))

class LinuxMonitor(HV):
    def run_shell(self, *args, **kwargs):
        raise RuntimeError("Linux probe stopped on first monitor exception; inspect saved context")

    # A single pre-Linux rendezvous parks all guest secondaries. No PSCI
    # calls, CPU_ON emulation or changes to a running Linux CPU's MMU state.
    def handle_hvc(self, ctx):
        if ctx.esr.ISS != 0x5350:
            return super().handle_hvc(ctx)
        assert not getattr(self, 'spin_bootstrapped', False)
        assert ctx.cpu_id == boot_cpu
        assert not (self.u.mrs(SCTLR_EL12) & ((1 << 0) | (1 << 2) | (1 << 12)))
        self.spin_bootstrapped = True
        for cpu, mpidr in enumerate(mpidrs):
            if cpu == boot_cpu:
                continue
            self.started_cpus[cpu] = (0, (mpidr >> 8) & 7, mpidr & 0xff)
            self.sysreg[cpu] = {}
            self.p.hv_start_secondary(cpu, spin_code.secondary_park,
                                      spin_page + cpu * 128,
                                      spin_page + cpu * 128 + 64, 0, 0)
        import time
        until = time.monotonic() + 5
        while True:
            self.p.dc_ivac(spin_page, 0x4000)
            ready = [cpu for cpu in range(6) if cpu != boot_cpu and
                     self.p.read64(spin_page + cpu * 128 + 64) == 1]
            if len(ready) == 5:
                break
            assert time.monotonic() < until, ('secondary holding loop not ready', ready)
        print('NEO_SPIN_TABLE_READY five secondaries parked; all6 CPUs; no PSCI', flush=True)
        return True

hv = LinuxMonitor(iface,p,u)
hv.init()
print("VUART mapped", hex(hv.adt["/arm-io/uart0"].get_reg(0)[0]), flush=True)
# Prepare the real loader-populated FDT. No Linux-side ADT decoding.
spin_page = u.memalign(0x4000, 0x4000)
spin_entry = u.memalign(0x4000, 0x4000)
iface.writemem(spin_page, bytes(0x4000))
p.dc_civac(spin_page, 0x4000)
loader = Loader(root,args.evidence,args.dtb)
dt = C.create_string_buffer(0x40000)
assert loader.open(loader.fixture,dt,len(dt)) == 0
# Reserve the resident monitor, all native stacks and both allocation heaps.
reserve = loader.lib.fdt_add_mem_rsv
reserve.argtypes = [C.c_void_p,C.c_uint64,C.c_uint64]
reserve.restype = C.c_int
monitor_base = u.ba.phys_base & ~0x3fff
assert reserve(dt,monitor_base,u.heap_top-monitor_base) == 0
if args.enable_gpu:
    node = loader.path(dt,b'/soc/gpu@480000000')
    assert node >= 0 and loader.set(dt,node,b'status',b'okay\0',5) == 0
    p.pmgr_adt_power_enable('/arm-io/sgx')
    p.pmgr_adt_power_enable('/arm-io/gfx-asc')
    p.pmgr_adt_power_enable('/arm-io/gfx1-asc')
# Load outside the resident monitor/Python heaps; Linux owns the rest of RAM.
image = args.image.read_bytes()
assert image[0x38:0x3c] == b'ARM\x64'
kernel_base = (u.heap_top + 0x1ffffff) & ~0x1ffffff
assert kernel_base + len(image) < u.ba.phys_base + u.ba.mem_size
u.compressed_writemem(kernel_base,image,True)
p.dc_cvau(kernel_base,len(image)); p.ic_ivau(kernel_base,len(image))
spin_source = (Path(__file__).parent/'neo-linux-spin-table.S').read_text()
spin_code = ARMAsm(f'hvc #0x5350\nldr x4, ={kernel_base:#x}\nbr x4\n' + spin_source, spin_entry)
assert len(spin_code.data) < 0x4000
iface.writemem(spin_entry, spin_code.data)
p.dc_cvau(spin_entry, len(spin_code.data)); p.ic_ivau(spin_entry, len(spin_code.data))
(args.evidence/'spin-table.S').write_text(spin_code.source)
(args.evidence/'spin-table.bin').write_bytes(spin_code.data)
initrd = args.initramfs.read_bytes()
initrd_base = u.memalign(0x10000,len(initrd))
u.compressed_writemem(initrd_base,initrd,True)
p.kboot_set_initrd(initrd_base,len(initrd))
p.kboot_set_chosen('bootargs','earlycon console=ttySAC0,115200 keep_bootcon '
                         'ignore_loglevel log_buf_len=2M initcall_debug '
                         'clk_ignore_unused pd_ignore_unused cpuidle.off=1 idle=yield panic=-1 '+ ' '.join(args.bootarg))
dtbase = u.memalign(0x4000,len(dt))
iface.writemem(dtbase,dt.raw)
assert p.kboot_prepare_dt(dtbase) == 0
# Read our own ELF's dt pointer; verify it by FDT magic before using it.
syms = subprocess.check_output(['nm',str(root/'build/m1n1-raw.elf')],text=True)
symbols = {r[2]:int(r[0],16) for line in syms.splitlines() if len(r:=line.split()) == 3}
fdt = p.read64(u.base + symbols['dt'] - symbols['_base'])
assert u.ba.phys_base <= fdt < u.ba.phys_base + u.ba.mem_size, hex(fdt)
header = iface.readmem(fdt,8)
assert header[:4] == b'\xd0\x0d\xfe\xed'
size = struct.unpack_from('>I',header,4)[0]
# Verify the actual loader handoff before any Linux GPU access.
actual_dt = C.create_string_buffer(iface.readmem(fdt,size),size)
assert loader.path(actual_dt, b'/psci') < 0, 'PSCI node must not be present'
cpus = loader.path(actual_dt, b'/cpus')
seen = set()
for cpu_node in loader.children(actual_dt, cpus):
    if loader.property(actual_dt, cpu_node, 'device_type') != b'cpu\0':
        continue
    mpidr = int.from_bytes(loader.property(actual_dt, cpu_node, 'reg'), 'big')
    cpu = mpidrs.index(mpidr)
    assert loader.property(actual_dt, cpu_node, 'enable-method') == b'spin-table\0'
    release = struct.pack('>Q', spin_page + cpu * 128)
    assert loader.set(actual_dt, cpu_node, b'cpu-release-addr', release, len(release)) == 0
    seen.add(cpu)
assert seen == set(range(6)), seen
iface.writemem(fdt, actual_dt.raw)
p.dc_civac(fdt, size)
(args.evidence/'populated.dtb').write_bytes(iface.readmem(fdt, size))
# Keep the guest's immutable FDT outside the resident monitor's allocation
# aperture, adjacent to its Image. Linux reserves its own FDT through memblock.
loader_fdt = fdt
fdt = (kernel_base + len(image) + 0x1fffff) & ~0x1fffff
assert fdt + size < u.ba.phys_base + u.ba.mem_size
iface.writemem(fdt, actual_dt.raw)
p.dc_civac(fdt, size)
assert iface.readmem(fdt, size) == actual_dt.raw
print(f'NEO_FDT_RELOCATED {loader_fdt:#x} -> {fdt:#x} immutable byte-identical', flush=True)

print('NEO_SPIN_TABLE_FDT_PASS all6 release words; no PSCI node', flush=True)

actual_gpu = loader.path(actual_dt,b'/soc/gpu@480000000')
assert loader.property(actual_dt,actual_gpu,'apple,neo-boot-abi') == struct.pack('>I',1)
assert loader.property(actual_dt,actual_gpu,'apple,firmware-build') == b'mBoot-18000.161.9\0'
assert loader.property(actual_dt,actual_gpu,'apple,sgx-perf-state-count') == struct.pack('<I',16)
print('NEO_FDT_HANDOFF_PASS actualbootABI1/firmware26.6.2/16performanceentries',flush=True)

ram_base = u.ba.phys_base & ~0xffffffff
hv.add_tracer(irange(ram_base,u.ba.mem_size_actual),'LINUX-RAM',TraceMode.OFF)
hv.pt_update()
# Existing VUART on the same verified serial-number device, bridged to stdout.
vuart = serial.Serial(VUART,115200,timeout=0.2)
stop = threading.Event()
def console():
    with (args.evidence/'dmesg.log').open('wb') as log:
        while not stop.is_set():
            data = vuart.read(vuart.in_waiting or 1)
            if data:
                log.write(data); log.flush()
                sys.stdout.write(data.decode('utf-8',errors='replace')); sys.stdout.flush()
thread = threading.Thread(target=console,daemon=True);thread.start()
if sys.stdin.isatty():
    def console_input():
        for line in sys.stdin:
            vuart.write(line.encode())
    threading.Thread(target=console_input,daemon=True).start()
(args.evidence/'launch.json').write_text(json.dumps(dict(device=DEVICE,vuart=VUART,
    boot_cpu=boot_cpu,cpus=6,gpu_enabled=args.enable_gpu,kernel_base=kernel_base,
    fdt=fdt,loader_fdt=loader_fdt,monitor_supplies='pre-Linux spin-table holding loops and VUART; GPU passthrough',spin_table_page=spin_page,spin_entry=spin_entry,PSCI=False,command=sys.argv,
    input_sha256={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in
        [args.image,args.dtb,args.initramfs,Path(__file__),Path(__file__).parent/'neo-linux-spin-table.S',root/'build/m1n1.bin',root/'build/m1n1-raw.elf']}),indent=2)+'\n')
hv.started_cpus[boot_cpu] = (0,(boot_mpidr>>8)&7,boot_mpidr&0xff)
hv.sysreg[boot_cpu] = {}
hv.default_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT,hv._handle_sigint)
hv.started = True
iface.dev.timeout = None
print(f'LINUX starting {kernel_base:#x}, FDT {fdt:#x}, all 6 CPUs',flush=True)
try:
    # Linux has not started: establish the same MMU/cache-off initial state
    # for the primary and every parked secondary before the one-time rendezvous.
    u.msr(SCTLR_EL12, u.mrs(SCTLR_EL12) & ~((1 << 0) | (1 << 2) | (1 << 12)))
    p.hv_start(spin_entry,fdt,0,0,0)
finally:
    stop.set();thread.join(timeout=1);vuart.close()
