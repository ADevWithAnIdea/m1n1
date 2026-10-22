#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the real Linux G16C probe with hardware GPU passthrough and VUART.

The monitor supplies PSCI CPU_ON and the existing VUART console. GPU registers,
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

DEVICE = '/dev/cu.usbmodemJPWWJRX2N01'
VUART = '/dev/cu.usbmodemJPWWJRX2N03'
if os.environ.get('M1N1DEVICE') != DEVICE:
    raise SystemExit('Select the verified Max explicitly with M1N1DEVICE=' + DEVICE)
root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('image', type=Path)
parser.add_argument('dtb', type=Path, help='16-CPU J616c test DTB compiled with M1N1_MONITOR')
parser.add_argument('initramfs', type=Path)
parser.add_argument('--evidence', type=Path, required=True)
parser.add_argument('--enable-gpu', action='store_true')
args = parser.parse_args()
args.evidence.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(root/'proxyclient'))
sys.path.insert(0, str(root.parent/'linux-g16c-g17p/drivers/gpu/drm/asahi/tests'))
from host_fdt import Loader
from m1n1.asm import BaseAsm
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
assert u.adt.model == 'Mac16,5' and p.get_chipid() == 0x6041
iface.tty_log = (args.evidence/'monitor.log').open('w')
iface.nop()
for name,expected in [('uart0',0x429200000),('aic',0x502400000),('sgx',0x288000000),('gfx-asc',0x28a600000)]:
    assert u.adt['/arm-io/'+name].get_reg(0)[0] == expected, name
p.smp_start_secondaries()
mpidrs = [0,1,2,3,0x10100,0x10101,0x10102,0x10103,0x10104,0x10105,
          0x10200,0x10201,0x10202,0x10203,0x10204,0x10205]
boot_mpidr = u.mrs(MPIDR_EL1) & 0xffffff
boot_cpu = mpidrs.index(boot_mpidr)
assert all(i == boot_cpu or p.smp_is_alive(i) for i in range(16))

class LinuxMonitor(HV):
    def run_shell(self, *args, **kwargs):
        raise RuntimeError("Linux probe stopped on first monitor exception; inspect saved context")

    def handle_hvc(self, ctx):
        if ctx.esr.ISS != 0:
            return super().handle_hvc(ctx)
        call, target, entry, context = ctx.regs[:4]
        result = -1
        if call == 0x84000000:  # PSCI_VERSION
            result = 0x10000
        elif call == 0x8400000a:  # PSCI_FEATURES
            result = 0 if target in (0x84000000,0x8400000a,0xc4000003,0x84000003,
                                    0xc4000004,0x84000004,0x84000006) else -1
        elif call == 0x84000006:  # MIGRATE_INFO_TYPE: no trusted OS
            result = 2
        elif call in (0xc4000004,0x84000004):  # AFFINITY_INFO
            result = 0 if target in mpidrs and mpidrs.index(target) in self.started_cpus else 1
        elif call in (0xc4000003,0x84000003):  # CPU_ON
            if target not in mpidrs:
                result = -2
            elif mpidrs.index(target) in self.started_cpus:
                result = -4
            else:
                cpu = mpidrs.index(target)
                print(f'LINUX CPU_ON cpu={cpu} mpidr={target:#x} entry={entry:#x}', flush=True)
                # Generic Max HV secondary startup inherits EL12 state for XNU.
                # Linux secondary_entry requires MMU/cache off, PSCI convention.
                saved = self.u.mrs(SCTLR_EL12)
                print("PSCI saved EL12",hex(saved),flush=True)
                try:
                    self.u.msr(SCTLR_EL12, saved & ~((1<<0)|(1<<2)|(1<<12)))
                    print("PSCI entering target startup",flush=True)
                    self.p.hv_start_secondary(cpu, entry, context, 0, 0, 0)
                    print("PSCI target startup returned",flush=True)
                finally:
                    self.u.msr(SCTLR_EL12, saved)
                    print("PSCI restored EL12",flush=True)
                self.started_cpus[cpu] = (0,(target >> 8) & 7,target & 0xff)
                self.sysreg[cpu] = {}
                result = 0
        else:
            print(f'LINUX unsupported PSCI {call:#x}', flush=True)
        ctx.regs[0] = result & ((1<<64)-1)
        # HVC saves the following PC already. Do not skip the next instruction.
        return True

hv = LinuxMonitor(iface,p,u)
hv.init()
print("VUART mapped", hex(hv.adt["/arm-io/uart0"].get_reg(0)[0]), flush=True)
# Prepare the real loader-populated FDT. No Linux-side ADT decoding.
loader = Loader(root,args.evidence,args.dtb)
dt = C.create_string_buffer(0x40000)
assert loader.open(loader.fixture,dt,len(dt)) == 0
# Reserve the resident monitor, all native stacks and both allocation heaps.
reserve = loader.lib.fdt_add_mem_rsv
reserve.argtypes = [C.c_void_p,C.c_uint64,C.c_uint64]
reserve.restype = C.c_int
monitor_base = u.base & ~0x3fff
assert reserve(dt,monitor_base,u.heap_top-monitor_base) == 0
if args.enable_gpu:
    node = loader.path(dt,b'/soc/gpu@288000000')
    assert node >= 0 and loader.set(dt,node,b'status',b'okay\0',5) == 0
    p.pmgr_adt_power_enable('/arm-io/sgx')
    p.pmgr_adt_power_enable('/arm-io/gfx-asc')
# Load outside the resident monitor/Python heaps; Linux owns the rest of RAM.
image = args.image.read_bytes()
assert image[0x38:0x3c] == b'ARM\x64'
kernel_base = (u.heap_top + 0x1ffffff) & ~0x1ffffff
assert kernel_base + len(image) < u.ba.phys_base + u.ba.mem_size
u.compressed_writemem(kernel_base,image,True)
p.dc_cvau(kernel_base,len(image)); p.ic_ivau(kernel_base,len(image))
initrd = args.initramfs.read_bytes()
initrd_base = u.memalign(0x10000,len(initrd))
u.compressed_writemem(initrd_base,initrd,True)
p.kboot_set_initrd(initrd_base,len(initrd))
p.kboot_set_chosen('bootargs','earlycon console=ttySAC0,115200 keep_bootcon '
                         'ignore_loglevel log_buf_len=2M initcall_debug '
                         'clk_ignore_unused pd_ignore_unused cpuidle.off=1 idle=yield panic=-1')
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
(args.evidence/'populated.dtb').write_bytes(iface.readmem(fdt,size))
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
    boot_cpu=boot_cpu,cpus=16,gpu_enabled=args.enable_gpu,kernel_base=kernel_base,
    fdt=fdt,monitor_supplies='PSCI and VUART; GPU passthrough',command=sys.argv,
    input_sha256={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in
        [args.image,args.dtb,args.initramfs,Path(__file__),root/'build/m1n1.bin',root/'build/m1n1-raw.elf']}),indent=2)+'\n')
hv.started_cpus[boot_cpu] = (0,(boot_mpidr>>8)&7,boot_mpidr&0xff)
hv.sysreg[boot_cpu] = {}
hv.default_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT,hv._handle_sigint)
hv.started = True
iface.dev.timeout = None
print(f'LINUX starting {kernel_base:#x}, FDT {fdt:#x}, all 16 CPUs',flush=True)
try:
    p.hv_start(kernel_base,fdt,0,0,0)
finally:
    stop.set();thread.join(timeout=1);vuart.close()
