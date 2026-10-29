# SPDX-License-Identifier: GPL-2.0-only
"""T8142/G17G driver mapping policy, using the existing UAT client.

Two native pre-init captures have the same 666-leaf shape after accounting for
three two-page allocations selected per boot.  The 602 stable host-RAM leaves
are represented as numeric runs.  The six variable leaves come from hardware-
data region-record addresses, and all 58 fixed I/O aliases come from the
hardware-data register records.  No captured page-table or RAM blob is used.
"""

from . import g17g_initdata


PAGE_SIZE = 0x4000
PAGE_MASK = PAGE_SIZE - 1

FLAGS_SHARED_EXECUTABLE = {
    "AttrIndex": 2, "AP": 1, "SH": 0, "AF": 1, "nG": 0,
    "PXN": 0, "UXN": 0, "OS": 1,
}
FLAGS_SHARED_UXN = {
    "AttrIndex": 2, "AP": 1, "SH": 0, "AF": 1, "nG": 0,
    "PXN": 0, "UXN": 1, "OS": 1,
}
FLAGS_NORMAL_UXN = {
    "AttrIndex": 0, "AP": 1, "SH": 0, "AF": 1, "nG": 0,
    "PXN": 0, "UXN": 1, "OS": 1,
}
FLAGS_DEVICE_EXECUTABLE = {
    "AttrIndex": 1, "AP": 1, "SH": 0, "AF": 1, "nG": 0,
    "PXN": 0, "UXN": 0, "OS": 1,
}
FLAGS_DEVICE_UXN = {
    "AttrIndex": 1, "AP": 1, "SH": 0, "AF": 1, "nG": 0,
    "PXN": 0, "UXN": 1, "OS": 1,
}

RAM_FLAG_CLASSES = {
    "shared_executable": FLAGS_SHARED_EXECUTABLE,
    "shared_uxn": FLAGS_SHARED_UXN,
    "normal_uxn": FLAGS_NORMAL_UXN,
}

# (DVA, page count, flag class).  These are the 602 leaves present at the same
# DVA with the same attributes in both native boots.  Fresh physical backing is
# intentionally absent from the recipe.
STABLE_RAM_RUNS = (
    (0xFFFFFC2000020000, 94, "shared_uxn"),
    (0xFFFFFC20001A0000, 1, "shared_executable"),
    (0xFFFFFC20001A8000, 1, "shared_executable"),
    (0xFFFFFC20001B0000, 1, "shared_executable"),
    (0xFFFFFC20001B8000, 1, "shared_executable"),
    (0xFFFFFC20001C0000, 1, "shared_uxn"),
    (0xFFFFFC20001C8000, 1, "shared_uxn"),
    (0xFFFFFC20001D0000, 1, "shared_uxn"),
    (0xFFFFFC20015D8000, 1, "shared_executable"),
    (0xFFFFFC20015E0000, 1, "shared_uxn"),
    (0xFFFFFC20015E8000, 1, "shared_uxn"),
    (0xFFFFFC20015F0000, 1, "shared_uxn"),
    (0xFFFFFC20C0018000, 37, "normal_uxn"),
    (0xFFFFFC20C00B0000, 129, "normal_uxn"),
    (0xFFFFFC20C02B8000, 38, "normal_uxn"),
    (0xFFFFFC20C0358000, 61, "normal_uxn"),
    (0xFFFFFC20C0450000, 85, "normal_uxn"),
    (0xFFFFFC20C05A8000, 1, "normal_uxn"),
    (0xFFFFFC20C05B0000, 1, "normal_uxn"),
    (0xFFFFFC20C05B8000, 2, "normal_uxn"),
    (0xFFFFFC20C05C8000, 3, "normal_uxn"),
    (0xFFFFFC20C05D8000, 3, "normal_uxn"),
    (0xFFFFFC20C05E8000, 4, "normal_uxn"),
    (0xFFFFFC20C0600000, 6, "normal_uxn"),
    (0xFFFFFC20C0620000, 1, "normal_uxn"),
    (0xFFFFFC20C0628000, 1, "normal_uxn"),
    (0xFFFFFC20C0630000, 13, "normal_uxn"),
    (0xFFFFFC20C0668000, 50, "normal_uxn"),
    (0xFFFFFC20C0738000, 13, "normal_uxn"),
    (0xFFFFFC20C0770000, 4, "normal_uxn"),
    (0xFFFFFC20C0788000, 10, "normal_uxn"),
    (0xFFFFFC20C07B8000, 1, "normal_uxn"),
    (0xFFFFFC20C07C8000, 3, "normal_uxn"),
    (0xFFFFFC20C07D8000, 1, "normal_uxn"),
    (0xFFFFFC20C07E8000, 2, "normal_uxn"),
    (0xFFFFFC20C07F8000, 2, "normal_uxn"),
    (0xFFFFFC20C0808000, 4, "normal_uxn"),
    (0xFFFFFC20C0820000, 2, "normal_uxn"),
    (0xFFFFFC20C0830000, 4, "normal_uxn"),
    (0xFFFFFC20C0848000, 2, "normal_uxn"),
    (0xFFFFFC20C0858000, 4, "normal_uxn"),
    (0xFFFFFC20C0870000, 2, "normal_uxn"),
    (0xFFFFFC20C0880000, 8, "normal_uxn"),
)

DYNAMIC_REGION_RECORD_COUNT = 3
DYNAMIC_REGION_PAGE_OFFSET = 0
DYNAMIC_REGION_PAGE_COUNT = 6
EXPECTED_RAM_PAGE_COUNT = 608
EXPECTED_IO_PAGE_COUNT = 58
EXPECTED_TOTAL_PAGE_COUNT = 666
BACKING_SIZE = EXPECTED_RAM_PAGE_COUNT * PAGE_SIZE

# Context zero's native low root is entirely an alias view of the firmware
# high-root RAM package.  Six stable runs and four eight-page region-record
# views account for all 299 leaves in two independent pre-init captures.
CONTEXT0_ALIAS_BASE = 0x7200000000
CONTEXT0_STABLE_ALIAS_RUNS = (
    (0x7200000000, 0xFFFFFC20C0018000, 37, False),
    (0x7200098000, 0xFFFFFC20C00B0000, 129, False),
    (0x72002A0000, 0xFFFFFC20C02B8000, 38, False),
    (0x7200340000, 0xFFFFFC20C0358000, 61, False),
    (0x7201838000, 0xFFFFFC20015E8000, 1, True),
    (0x7201840000, 0xFFFFFC20015F0000, 1, True),
)
CONTEXT0_REGION_ALIAS_PAGE_COUNT = 8
EXPECTED_CONTEXT0_ALIAS_PAGE_COUNT = 299



FLAGS_CONTEXT0_EXECUTABLE = {
    "AttrIndex": 2, "AP": 2, "SH": 0, "AF": 1, "nG": 1,
    "PXN": 0, "UXN": 0, "OS": 1,
}
FLAGS_CONTEXT0_UXN = {
    "AttrIndex": 2, "AP": 2, "SH": 0, "AF": 1, "nG": 1,
    "PXN": 0, "UXN": 1, "OS": 1,
}



def _align_down(value):
    return value & ~PAGE_MASK


def _align_up(value):
    return (value + PAGE_MASK) & ~PAGE_MASK


def _expand_runs(runs, include_pa=False):
    pages = {}
    for run in runs:
        va = run["va"]
        pa = run.get("pa")
        for index in range(run["page_count"]):
            page_va = va + index * PAGE_SIZE
            record = {"flags": dict(run["flags"])}
            if include_pa:
                record["pa"] = pa + index * PAGE_SIZE
            if page_va in pages:
                raise ValueError("numeric firmware-root runs overlap")
            pages[page_va] = record
    return pages


def build_ram_runs(region_records):
    """Build all 608 fresh-RAM runs from stable and dynamic inputs."""
    if len(region_records) != g17g_initdata.HWDATA_REGION_RECORD_COUNT:
        raise ValueError("numeric region-record count changed")
    input_runs = [
        {
            "va": va,
            "page_count": page_count,
            "flags": dict(RAM_FLAG_CLASSES[flag_class]),
            "source": "stable numeric RAM run",
        }
        for va, page_count, flag_class in STABLE_RAM_RUNS
    ]
    for index, record in enumerate(
        region_records[:DYNAMIC_REGION_RECORD_COUNT]
    ):
        address = int(record["address_0c"])
        if not address or address & PAGE_MASK:
            raise ValueError("numeric dynamic region address is not page aligned")
        input_runs.append({
            "va": address + DYNAMIC_REGION_PAGE_OFFSET,
            "page_count": DYNAMIC_REGION_PAGE_COUNT,
            "flags": dict(FLAGS_NORMAL_UXN),
            "source": "hardware-data region record %d" % index,
        })
    # Each dynamic six-page run overlaps four leaves in the stable skeleton and
    # contributes two boot-variable leaves.  Preserve that measured aliasing
    # while returning a non-overlapping set of runs suitable for allocation.
    pages = {}
    for run in input_runs:
        for page_index in range(run["page_count"]):
            va = run["va"] + page_index * PAGE_SIZE
            old = pages.get(va)
            if old is not None and old["flags"] != run["flags"]:
                raise ValueError("numeric firmware-root RAM runs conflict")
            if old is None:
                pages[va] = {
                    "flags": dict(run["flags"]),
                    "sources": [run["source"]],
                }
            elif run["source"] not in old["sources"]:
                old["sources"].append(run["source"])
    if len(pages) != EXPECTED_RAM_PAGE_COUNT:
        raise ValueError(
            "numeric firmware-root RAM recipe has %d pages, expected %d"
            % (len(pages), EXPECTED_RAM_PAGE_COUNT)
        )
    runs = []
    for va in sorted(pages):
        page = pages[va]
        if (
            runs
            and va == runs[-1]["va"] + runs[-1]["page_count"] * PAGE_SIZE
            and page["flags"] == runs[-1]["flags"]
            and page["sources"] == runs[-1]["sources"]
        ):
            runs[-1]["page_count"] += 1
            continue
        runs.append({
            "va": va,
            "page_count": 1,
            "flags": dict(page["flags"]),
            "source": ", ".join(page["sources"]),
            "sources": list(page["sources"]),
        })
    return runs


def build_io_runs(register_records):
    """Derive all fixed I/O aliases from nonempty hardware-data records."""
    if len(register_records) != g17g_initdata.HWDATA_REGISTER_RECORD_COUNT:
        raise ValueError("numeric register-record count changed")
    pages = {}
    for index, record in enumerate(register_records):
        pa = int(record["field_00"])
        va = int(record["field_08"])
        size = int(record["word_10"])
        if not (pa or va or size):
            continue
        if not (pa and va and size):
            raise ValueError("numeric nonempty register record is incomplete")
        if (pa & PAGE_MASK) != (va & PAGE_MASK):
            raise ValueError("numeric register alias page offsets disagree")
        if int(record["word_14"]) > size:
            raise ValueError("numeric register visible size exceeds map size")
        mode = int(record["word_20"])
        if mode == 0:
            flags = FLAGS_DEVICE_EXECUTABLE
        elif mode == 2:
            flags = FLAGS_DEVICE_UXN
        else:
            raise ValueError("numeric register mapping mode is unobserved")
        start_va = _align_down(va)
        start_pa = _align_down(pa)
        end_va = _align_up(va + size)
        for page_va in range(start_va, end_va, PAGE_SIZE):
            page_pa = start_pa + page_va - start_va
            candidate = {"pa": page_pa, "flags": dict(flags)}
            old = pages.get(page_va)
            if old is not None and old != candidate:
                raise ValueError("numeric register mappings conflict")
            pages[page_va] = candidate

    if len(pages) != EXPECTED_IO_PAGE_COUNT:
        raise ValueError(
            "numeric firmware-root I/O recipe has %d pages, expected %d"
            % (len(pages), EXPECTED_IO_PAGE_COUNT)
        )
    runs = []
    for va in sorted(pages):
        page = pages[va]
        if (
            runs
            and va == runs[-1]["va"] + runs[-1]["page_count"] * PAGE_SIZE
            and page["pa"]
            == runs[-1]["pa"] + runs[-1]["page_count"] * PAGE_SIZE
            and page["flags"] == runs[-1]["flags"]
        ):
            runs[-1]["page_count"] += 1
            continue
        runs.append({
            "va": va,
            "pa": page["pa"],
            "page_count": 1,
            "flags": dict(page["flags"]),
            "source": "hardware-data register records",
        })
    return runs


def build_firmware_root_recipe(hwdata_fields):
    """Return the complete independently reproduced 666-leaf recipe."""
    ram_runs = build_ram_runs(hwdata_fields["region_records"])
    io_runs = build_io_runs(hwdata_fields["register_records"])
    ram_pages = _expand_runs(ram_runs)
    io_pages = _expand_runs(io_runs, include_pa=True)
    overlap = set(ram_pages) & set(io_pages)
    if overlap:
        raise ValueError("numeric RAM and I/O firmware-root mappings overlap")
    if len(ram_pages) + len(io_pages) != EXPECTED_TOTAL_PAGE_COUNT:
        raise ValueError("numeric complete firmware-root mapping count changed")
    seed_pages = (
        set(g17g_initdata.PREINIT_CLOSURE_PAGE_DVAS)
        | set(g17g_initdata.PREINIT_AUXILIARY_PAGE_DVAS)
    )
    missing = seed_pages - set(ram_pages)
    if missing:
        raise ValueError("numeric seed pages are absent from the RAM recipe")
    return {"ram_runs": ram_runs, "io_runs": io_runs}


def expand_firmware_root_recipe(recipe):
    """Expand a complete recipe to one record per DVA page."""
    ram_pages = _expand_runs(recipe["ram_runs"])
    io_pages = _expand_runs(recipe["io_runs"], include_pa=True)
    result = {
        va: {**record, "content_class": "captured-ram"}
        for va, record in ram_pages.items()
    }
    for va, record in io_pages.items():
        if va in result:
            raise ValueError("numeric expanded firmware-root recipe overlaps")
        result[va] = {**record, "content_class": "outside-capture"}
    if len(result) != EXPECTED_TOTAL_PAGE_COUNT:
        raise ValueError("numeric expanded firmware-root mapping count changed")
    return result


def build_context0_alias_runs(region_records):
    """Build the complete 299-leaf low-to-high alias recipe."""
    if len(region_records) != g17g_initdata.HWDATA_REGION_RECORD_COUNT:
        raise ValueError("numeric region-record count changed")
    runs = [
        {
            "low_va": low_va,
            "high_va": high_va,
            "page_count": page_count,
            "flags": dict(
                FLAGS_CONTEXT0_UXN if uxn else FLAGS_CONTEXT0_EXECUTABLE
            ),
            "source": "stable numeric context-zero alias run",
        }
        for low_va, high_va, page_count, uxn
        in CONTEXT0_STABLE_ALIAS_RUNS
    ]
    for index, record in enumerate(region_records):
        low_offset = int(record["word_04"])
        high_va = int(record["address_0c"])
        if not low_offset or low_offset & PAGE_MASK:
            raise ValueError("numeric context-zero region offset is unaligned")
        if not high_va or high_va & PAGE_MASK:
            raise ValueError("numeric context-zero high alias is unaligned")
        runs.append({
            "low_va": CONTEXT0_ALIAS_BASE + low_offset,
            "high_va": high_va,
            "page_count": CONTEXT0_REGION_ALIAS_PAGE_COUNT,
            "flags": dict(FLAGS_CONTEXT0_UXN),
            "source": "hardware-data region record %d" % index,
        })
    expanded = expand_context0_alias_runs(runs)
    if len(expanded) != EXPECTED_CONTEXT0_ALIAS_PAGE_COUNT:
        raise ValueError(
            "numeric context-zero alias recipe has %d pages, expected %d"
            % (len(expanded), EXPECTED_CONTEXT0_ALIAS_PAGE_COUNT)
        )
    return tuple(runs)


def expand_context0_alias_runs(runs):
    """Expand low aliases to one low-DVA/high-DVA record per page."""
    result = {}
    for run in runs:
        for index in range(int(run["page_count"])):
            low_va = int(run["low_va"]) + index * PAGE_SIZE
            high_va = int(run["high_va"]) + index * PAGE_SIZE
            record = {
                "high_va": high_va,
                "flags": dict(run["flags"]),
                "source": run["source"],
            }
            old = result.get(low_va)
            if old is not None and old != record:
                raise ValueError("numeric context-zero alias runs conflict")
            result[low_va] = record
    return result


def collect_firmware_root_table_pages(uat, root_pa, virtual_addresses):
    """Ask the UAT client for tables beneath this driver-owned root."""
    return uat.root_table_pages(root_pa)


def materialize_context0_alias_root(
    uat, proxy, root_pa, runs, high_ram_pages, verify=True,
    initialize_root=True,
):
    """Build context zero's low root as aliases of source-owned high RAM.

    A caller reconstructing an observed physical table topology may preseed
    the root's table descriptors and pass ``initialize_root=False``.  No table
    bytes are imported: :meth:`UAT.iomap_at_root` still source-generates every
    leaf descriptor and will allocate only if a required preseeded edge is
    absent.
    """
    if not root_pa or root_pa & PAGE_MASK:
        raise ValueError("numeric context-zero root page is not aligned")
    expanded = expand_context0_alias_runs(runs)
    if len(expanded) != EXPECTED_CONTEXT0_ALIAS_PAGE_COUNT:
        raise ValueError("numeric context-zero alias mapping count changed")
    if initialize_root:
        proxy.memset32(root_pa, 0, PAGE_SIZE)
    aliases = {}
    for low_va, record in sorted(expanded.items()):
        high_va = int(record["high_va"])
        if high_va not in high_ram_pages:
            raise ValueError(
                "numeric context-zero alias target is absent at %#x" % high_va
            )
        pa = int(high_ram_pages[high_va])
        uat.iomap_at_root(
            root_pa, low_va, pa, PAGE_SIZE, **record["flags"]
        )
        aliases[low_va] = {"high_va": high_va, "pa": pa}
    uat.flush_dirty()
    uat.invalidate_root_walk_cache()
    table_pages = collect_firmware_root_table_pages(uat, root_pa, aliases)
    if verify:
        for low_va, record in sorted(aliases.items()):
            translated = uat.iotranslate_root(root_pa, low_va, PAGE_SIZE)
            if translated != [(record["pa"], PAGE_SIZE)]:
                raise RuntimeError(
                    "numeric context-zero translation mismatch at %#x" % low_va
                )
    return {"aliases": aliases, "table_pages": table_pages}








def build_backing_plan_for_pages(recipe, ram_pages):
    """Build the mapping plan for an explicit numeric DVA-to-PA assignment."""
    expanded = expand_firmware_root_recipe(recipe)
    ram_vas = sorted(
        va for va, item in expanded.items()
        if item["content_class"] == "captured-ram"
    )
    ram_pages = {int(va): int(pa) for va, pa in ram_pages.items()}
    if set(ram_pages) != set(ram_vas):
        missing = sorted(set(ram_vas) - set(ram_pages))
        extra = sorted(set(ram_pages) - set(ram_vas))
        raise ValueError(
            "numeric backing DVA set changed: missing=%s extra=%s"
            % ([hex(x) for x in missing], [hex(x) for x in extra])
        )
    if any(not pa or pa & PAGE_MASK for pa in ram_pages.values()):
        raise ValueError("numeric backing contains an unaligned physical page")
    if len(set(ram_pages.values())) != len(ram_pages):
        raise ValueError("numeric backing aliases two source RAM DVAs")

    ram_runs = []
    for va in ram_vas:
        pa = ram_pages[va]
        flags = expanded[va]["flags"]
        if (
            ram_runs
            and va == ram_runs[-1]["va"] + ram_runs[-1]["page_count"] * PAGE_SIZE
            and pa == ram_runs[-1]["pa"] + ram_runs[-1]["page_count"] * PAGE_SIZE
            and flags == ram_runs[-1]["flags"]
        ):
            ram_runs[-1]["page_count"] += 1
        else:
            ram_runs.append({
                "va": va,
                "pa": pa,
                "page_count": 1,
                "flags": dict(flags),
            })
    if len(ram_pages) != EXPECTED_RAM_PAGE_COUNT:
        raise ValueError("numeric fresh backing page count changed")
    physical_runs = []
    for pa in sorted(ram_pages.values()):
        if (
            physical_runs
            and pa == physical_runs[-1]["pa"]
            + physical_runs[-1]["page_count"] * PAGE_SIZE
        ):
            physical_runs[-1]["page_count"] += 1
        else:
            physical_runs.append({"pa": pa, "page_count": 1})
    return {
        "backing_pa": None,
        "backing_size": BACKING_SIZE,
        "ram_runs": ram_runs,
        "ram_pages": ram_pages,
        "physical_runs": physical_runs,
        "io_runs": [dict(run) for run in recipe["io_runs"]],
    }


def build_backing_plan(recipe, backing_pa):
    """Assign fresh contiguous physical backing to the recipe's RAM leaves."""
    if not backing_pa or backing_pa & PAGE_MASK:
        raise ValueError("numeric firmware-root backing must be page aligned")
    expanded = expand_firmware_root_recipe(recipe)
    ram_vas = sorted(
        va for va, item in expanded.items()
        if item["content_class"] == "captured-ram"
    )
    plan = build_backing_plan_for_pages(
        recipe,
        {
            va: backing_pa + index * PAGE_SIZE
            for index, va in enumerate(ram_vas)
        },
    )
    plan["backing_pa"] = backing_pa
    return plan


def materialize_firmware_root(
    uat,
    iface,
    util,
    proxy,
    root_pa,
    recipe,
    seed_pages,
    backing_pa=None,
    ram_pages=None,
    verify=True,
    initialize_backing=True,
):
    """Allocate, zero, map, seed, and publish one host-owned firmware root.

    ``root_pa`` is an already-selected L1 root.  It may be a fresh zeroed page
    or a boot-provided shared root whose firmware mappings must be preserved.
    This helper does not select which root the ASC consumes; publication is a
    platform decision made by the caller.
    """
    if not root_pa or root_pa & PAGE_MASK:
        raise ValueError("numeric firmware-root page is not aligned")
    if backing_pa is not None and ram_pages is not None:
        raise ValueError("choose contiguous backing or explicit RAM pages")
    if backing_pa is None and ram_pages is None:
        backing_pa = util.memalign(PAGE_SIZE, BACKING_SIZE)
    plan = (
        build_backing_plan_for_pages(recipe, ram_pages)
        if ram_pages is not None
        else build_backing_plan(recipe, backing_pa)
    )
    if initialize_backing:
        for run in plan["physical_runs"]:
            proxy.memset32(
                run["pa"], 0, run["page_count"] * PAGE_SIZE
            )

    for run in plan["ram_runs"]:
        uat.iomap_at_root(
            root_pa, run["va"], run["pa"],
            run["page_count"] * PAGE_SIZE,
            **run["flags"],
        )
    for run in plan["io_runs"]:
        uat.iomap_at_root(
            root_pa, run["va"], run["pa"],
            run["page_count"] * PAGE_SIZE,
            **run["flags"],
        )
    uat.flush_dirty()
    uat.invalidate_root_walk_cache()
    plan["table_pages"] = collect_firmware_root_table_pages(
        uat, root_pa, expand_firmware_root_recipe(recipe)
    )

    unknown = set(seed_pages) - set(plan["ram_pages"])
    if unknown:
        raise ValueError("numeric seed page is absent from fresh RAM backing")
    if initialize_backing:
        for va, data in sorted(seed_pages.items()):
            if len(data) != PAGE_SIZE:
                raise ValueError("numeric seed page has the wrong size")
            iface.writemem(plan["ram_pages"][va], data)
    for run in plan["physical_runs"]:
        proxy.dc_civac(run["pa"], run["page_count"] * PAGE_SIZE)
    util.inst("dsb sy")

    if verify:
        for va, expected_pa in sorted(plan["ram_pages"].items()):
            translated = uat.iotranslate_root(root_pa, va, PAGE_SIZE)
            if translated != [(expected_pa, PAGE_SIZE)]:
                raise RuntimeError(
                    "numeric firmware-root translation mismatch at %#x" % va
                )
    for va, data in sorted(seed_pages.items()):
        if bytes(iface.readmem(plan["ram_pages"][va], PAGE_SIZE)) != data:
            raise RuntimeError(
                "numeric firmware-root seed mismatch at %#x" % va
            )
    return plan


def prepare_firmware_backing(
    iface, util, proxy, recipe, seed_pages, backing_pa=None, ram_pages=None,
):
    """Allocate and seed the high-package RAM before firmware management."""
    if backing_pa is not None and ram_pages is not None:
        raise ValueError("choose contiguous backing or explicit RAM pages")
    if backing_pa is None and ram_pages is None:
        backing_pa = util.memalign(PAGE_SIZE, BACKING_SIZE)
    plan = (
        build_backing_plan_for_pages(recipe, ram_pages)
        if ram_pages is not None
        else build_backing_plan(recipe, backing_pa)
    )
    unknown = set(seed_pages) - set(plan["ram_pages"])
    if unknown:
        raise ValueError("numeric seed page is absent from fresh RAM backing")
    for run in plan["physical_runs"]:
        proxy.memset32(run["pa"], 0, run["page_count"] * PAGE_SIZE)
    for va, data in sorted(seed_pages.items()):
        if len(data) != PAGE_SIZE:
            raise ValueError("numeric seed page has the wrong size")
        iface.writemem(plan["ram_pages"][va], data)
    for run in plan["physical_runs"]:
        proxy.dc_civac(run["pa"], run["page_count"] * PAGE_SIZE)
    util.inst("dsb sy")
    for va, data in sorted(seed_pages.items()):
        if bytes(iface.readmem(plan["ram_pages"][va], PAGE_SIZE)) != data:
            raise RuntimeError(
                "numeric firmware-root seed mismatch at %#x" % va
            )
    return plan
