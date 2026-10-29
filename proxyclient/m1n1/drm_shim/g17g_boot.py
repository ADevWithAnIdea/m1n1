# SPDX-License-Identifier: GPL-2.0-only
"""T8142 source-built firmware initialization, independent of experiments.

This is the standard-ASC first-work boot path. It stops at the two initdata
ACKs: no test shader, work kick, capture loader, or submission is implicit.
Both DRM submission profiles use the same canonical initialization. Mixed
history allocation, management sequencing and work publication are later stages.
The caller supplies an already connected proxy and owns the reset boundary.
"""

import math
from pathlib import Path
import secrets
import struct
import time

from m1n1.fw.agx.handoff import PPL_MAGIC
from m1n1.fw.asc import StandardASC
from m1n1.fw.asc.base import ASCBaseEndpoint, ASCMessage1, msg_handler
from m1n1.hw.uat import UAT, TTBR, PTE, Page_PTE
from m1n1.utils import Register64

from . import g17g, g17g_defaults, g17g_initdata, g17g_uat
from .g17g_crash import G17GDataOnlyCrashEndpoint
from .g17g_mapping_client import RootMappingClient


PAGE_SIZE = 0x4000
INSTANCE_PATHS = (
    ("primary", "/arm-io/gfx-asc", g17g_initdata.PRIMARY_ROOT_ADDRESS),
    ("secondary", "/arm-io/gfx1-asc", g17g_initdata.SECONDARY_ROOT_ADDRESS),
)
POWER_PATHS = tuple(path for _, path, _ in INSTANCE_PATHS) + ("/arm-io/sgx",)
_MAINTAIN_RANGES = (
    "mov x8, x0; mov x9, x1; cbz x9, 3f; dsb osh; 1: "
    "ldp x10, x11, [x8], #16; 2: "
    "sys #3, c7, c3, #4, x10; sys #3, c7, c3, #5, x10; "
    "add x10, x10, #0x80; cmp x10, x11; b.lo 2b; "
    "subs x9, x9, #1; b.ne 1b; dsb osh; isb; 3:"
)


class G17GUAT(UAT):
    """Explicit M5 geometry; independent of legacy Ver's import-time state."""

    L0_OFF = 42
    L1_SIZE = 64
    LEVELS = ((42, 2, TTBR), (36, 64, PTE),
              (25, 2048, PTE), (14, 2048, Page_PTE))


def physical_page_runs(pages):
    """Validate all owned pages before publication and coalesce neighbors."""
    pages = tuple(pages)
    if any(type(pa) is not int or not 0 < pa < (1 << 42) or
           pa % PAGE_SIZE for pa in pages):
        raise ValueError("invalid owned physical page")
    runs = []
    for pa in sorted(set(pages)):
        if runs and pa == runs[-1][0] + runs[-1][1]:
            runs[-1] = (runs[-1][0], runs[-1][1] + PAGE_SIZE)
        else:
            runs.append((pa, PAGE_SIZE))
    return tuple(runs)


def publish_pages(util, pages, *, coprocessor=True):
    """Publish host-owned data/tables using the proven coprocessor sequence."""
    runs = physical_page_runs(pages)
    if not runs:
        return runs
    proxy, iface = util.proxy, util.iface
    for pa, size in runs:
        proxy.dc_civac(pa, size)
    if coprocessor:
        encoded = b"".join(struct.pack("<QQ", pa, pa + size) for pa, size in runs)
        with util.heap.guarded_malloc(len(encoded)) as list_pa:
            iface.writemem(list_pa, encoded)
            proxy.dc_civac(list_pa, len(encoded))
            util.inst(_MAINTAIN_RANGES, list_pa, len(runs))
    util.inst("dsb sy")
    return runs


def wait_until(asces, predicate, timeout, label):
    """Bounded, fair mailbox pumping; a busy ASC cannot starve its peer."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("firmware wait needs a finite positive timeout")
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError("G17G %s timeout" % label)
        for asc in asces:
            asc.work()  # At most one message, unlike work_pending().


class GPUMessage(Register64):
    TYPE = 63, 48


class FirmwareEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GPUMessage
    SHORT = "fw"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.init_ack = False
        self.ack_message = None
        self.event_count = 0

    @msg_handler(0x09)
    def init_complete(self, msg):
        self.init_ack = True
        self.ack_message = int(msg)
        return True

    @msg_handler(0x42)
    def event(self, msg):
        self.event_count += 1
        return True


class DoorbellEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GPUMessage
    SHORT = "doorbell"


class G17GASC(StandardASC):
    ENDPOINTS = {1: G17GDataOnlyCrashEndpoint,
                 0x20: FirmwareEndpoint, 0x21: DoorbellEndpoint}

    def __init__(self, util, base, name, crash_directory, trace=None):
        self.asc_base = int(base)
        self.coldboot_name = name
        self.crash_output_directory = crash_directory
        self.trace_callback = trace
        super().__init__(util, base)

    def _trace(self, direction, msg0, msg1):
        if self.trace_callback is not None:
            self.trace_callback(self.coldboot_name, direction,
                                int(msg0), int(msg1) & 0xff)

    def send(self, msg0, msg1):
        self._trace("W", msg0, msg1)
        return super().send(msg0, msg1)

    def recv(self):
        msg0, msg1 = super().recv()
        if msg0 is not None:
            self._trace("R", msg0, msg1)
        return msg0, msg1

    def start_management(self, timeout):
        self.asc.CPU_CONTROL.set(RUN=1)
        self.mgmt.start()
        wait_until((self,), lambda: self.mgmt.iop_power_state == 0x20 and
                   self.mgmt.ap_power_state == 0x20, timeout, "management")


class G17GBootRuntime:
    """One-shot owner of source initialization allocations and both ASCs.

    Failure retains allocations/evidence and forbids another boot in this
    object. A fresh hardware reset and fresh runtime are required; freeing
    pages underneath possibly running firmware is never an error unwind.
    """

    def __init__(self, util, crash_directory, *, trace=None):
        self.u, self.p, self.iface = util, util.proxy, util.iface
        self.crash_directory = Path(crash_directory)
        if not self.crash_directory.is_dir():
            raise ValueError("caller must create a crash-evidence directory")
        self.trace = trace
        self.state = "new"
        self.asces = []
        self.evidence = {"captured_input": None, "execution_claim": "none"}

    def _check_target(self):
        if int(self.u.adt["/chosen"].chip_id) != g17g.CHIP_ID:
            raise RuntimeError("G17G boot requires T8142")
        for path in POWER_PATHS:
            if path not in self.u.adt:
                raise RuntimeError("missing required ADT node %s" % path)
        sgx = self.u.adt["/arm-io/sgx"]
        shared, size, l2, handoff = map(int, (
            sgx.gfx_shared_region_base, sgx.gfx_shared_region_size,
            sgx.gfx_shared_l2_region_base, sgx.gfx_handoff_base))
        physical_page_runs((shared, l2, handoff))
        if size < 2 * PAGE_SIZE or size % (2 * PAGE_SIZE):
            raise RuntimeError("invalid dual-firmware shared region")
        if shared + size > (1 << 42):
            raise RuntimeError("firmware shared region exceeds physical range")
        self.shared_l2_pa, self.handoff_pa = l2, handoff
        self.firmware_roots = dict(primary=shared, secondary=shared + size // 2)

    def _prepare(self, dynamic_u32, verify):
        self._check_target()
        u, p, iface = self.u, self.p, self.iface
        regions = g17g_defaults.CANONICAL_REGION_ADDRESSES
        self.fields = g17g_defaults.canonical_preinit_fields(regions)
        seeds = g17g_defaults.build_canonical_seed_pages(dynamic_u32, regions)
        self.recipe = g17g_uat.build_firmware_root_recipe(self.fields["hwdata_fields"])
        expanded = g17g_uat.expand_firmware_root_recipe(self.recipe)
        aliases = g17g_uat.build_context0_alias_runs(
            self.fields["hwdata_fields"]["region_records"])
        self.uat = uat = RootMappingClient(G17GUAT(iface, u))
        backing = g17g_uat.prepare_firmware_backing(iface, u, p, self.recipe, seeds)
        self.backing = backing
        p.memset32(self.handoff_pa, 0, PAGE_SIZE)
        uat.handoff.reg.MAGIC_AP.val = PPL_MAGIC
        uat.handoff.reg.CUR_CTX.val = 0xffff
        uat.handoff.reg.UNK2.val = 1
        p.dc_civac(self.handoff_pa, PAGE_SIZE)
        self.context0_low_root = int(uat.ttbr0_base)
        self.context0 = g17g_uat.materialize_context0_alias_root(
            uat, p, self.context0_low_root, aliases, backing["ram_pages"],
            verify=verify)
        self.context0_high_root = int(u.memalign(PAGE_SIZE, PAGE_SIZE))
        p.memset32(self.context0_high_root, 0, PAGE_SIZE)
        uat.set_l0(0, 0, self.context0_low_root, 0)
        uat.set_l0(0, 1, self.context0_high_root, 0)
        uat.flush_dirty()
        uat.invalidate_cache()

        shift, count, _ = uat.LEVELS[1]
        indexes = {(va >> shift) & (count - 1) for va in expanded}
        if len(indexes) != 1:
            raise RuntimeError("source high package spans multiple root entries")
        self.high_index = indexes.pop()
        p.memset32(self.shared_l2_pa, 0, PAGE_SIZE)
        self.synthetic_high_root = int(u.memalign(PAGE_SIZE, PAGE_SIZE))
        p.memset32(self.synthetic_high_root, 0, PAGE_SIZE)
        link = PTE(VALID=1, TYPE=1)
        link.set_offset(self.shared_l2_pa)
        uat.write_pte(self.synthetic_high_root, self.high_index, count, link)
        self.plan = g17g_uat.materialize_firmware_root(
            uat, iface, u, p, self.synthetic_high_root, self.recipe, seeds,
            backing_pa=backing["backing_pa"], verify=verify,
            initialize_backing=False)
        if self.shared_l2_pa not in self.plan["table_pages"]:
            raise RuntimeError("source map did not descend through common L2")
        self.l2_before = bytes(iface.readmem(self.shared_l2_pa, PAGE_SIZE))
        self.context0_pair = (int(p.read64(uat.gpu_region)),
                              int(p.read64(uat.gpu_region + 8)))
        pages = set(self.context0["table_pages"]) | set(self.plan["table_pages"])
        pages.update(backing["ram_pages"].values())
        pages.update((self.context0_high_root, uat.gpu_region, self.handoff_pa))
        self.published_runs = publish_pages(u, pages, coprocessor=self.profile == "standard")
        self.evidence.update(seed_pages=len(seeds), ram_pages=len(backing["ram_pages"]),
                             published_pages=len(pages), root_leaves=len(expanded),
                             auxiliary_dynamic_u32=dynamic_u32,
                             uat_l0_shift=uat.L0_OFF, uat_l1_entries=uat.L1_SIZE)

    def _validate_live_roots(self):
        uat, p = self.uat, self.p
        current = (int(p.read64(uat.gpu_region)), int(p.read64(uat.gpu_region + 8)))
        if current != self.context0_pair:
            raise RuntimeError("ASC management changed context zero")
        if int(uat.ttbr1_base) != self.firmware_roots["primary"]:
            raise RuntimeError("UAT did not adopt the primary shared upper root")
        p.dc_ivac(self.shared_l2_pa, PAGE_SIZE)
        if bytes(self.iface.readmem(self.shared_l2_pa, PAGE_SIZE)) != self.l2_before:
            raise RuntimeError("ASC management changed the prebuilt common L2")
        shift, count, ptecls = uat.LEVELS[1]
        for name, _, descriptor in INSTANCE_PATHS:
            root = self.firmware_roots[name]
            index = (descriptor >> shift) & (count - 1)
            pte = uat.fetch_pte(root, index, count, ptecls)
            if not pte.valid() or pte.block() or int(pte.offset()) != self.shared_l2_pa:
                raise RuntimeError("%s firmware shared-root edge mismatch" % name)
            translated = uat.iotranslate_root(root, descriptor, PAGE_SIZE)
            if translated != [(self.plan["ram_pages"][descriptor], PAGE_SIZE)]:
                raise RuntimeError("%s initdata translation mismatch" % name)

    def boot(self, *, timeout=5.0, dynamic_u32=None, verify=False, profile="standard"):
        if self.state != "new":
            raise RuntimeError("G17G boot is one-shot; reset before reinitializing")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("boot timeout must be finite and positive")
        if profile not in ("standard", "compute", "mixed"):
            raise ValueError("unimplemented G17G boot profile")
        if dynamic_u32 is None:
            dynamic_u32 = secrets.randbits(32)
        if type(dynamic_u32) is not int or not 0 <= dynamic_u32 < (1 << 32):
            raise ValueError("auxiliary value must fit u32")
        started = time.monotonic()
        self.profile = profile
        self.evidence["profile"] = profile
        self.evidence["initialization_profile"] = "standard" if profile == "standard" else "compute"
        self.state = "preparing"
        try:
            self._prepare(dynamic_u32, verify)
            self.state = "booting"
            for path in POWER_PATHS:
                self.p.pmgr_adt_power_enable(path)
            for name, path, _ in INSTANCE_PATHS:
                asc = G17GASC(self.u, int(self.u.adt[path].get_reg(0)[0]),
                              name, self.crash_directory, self.trace)
                self.asces.append(asc)
            for asc in self.asces:
                asc.start_management(timeout)
                if profile in ("compute", "mixed"):
                    asc.start_ep(0x20)
                    asc.start_ep(0x21)
            self._validate_live_roots()
            if profile not in ("compute", "mixed"):
                for asc in self.asces:
                    asc.start_ep(0x20)
                    asc.start_ep(0x21)
            for asc, (_, _, descriptor) in zip(self.asces, INSTANCE_PATHS):
                msg = (g17g.MSG_INITDATA << 48) | (descriptor & ((1 << 44) - 1))
                asc.send(msg, ASCMessage1(EP=0x20))
            wait_until(self.asces, lambda: all(asc.fw.init_ack for asc in self.asces),
                       timeout, "dual initdata ACK")
            self.state = "ready"
            self.evidence["init_acks"] = {
                asc.coldboot_name: asc.fw.ack_message for asc in self.asces}
        except Exception as error:
            self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
        return self
