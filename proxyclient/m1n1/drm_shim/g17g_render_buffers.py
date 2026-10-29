# SPDX-License-Identifier: GPL-2.0-only
"""Per-render tilemap, heap metadata and TPC storage, retained by its context."""
from dataclasses import dataclass

PAGE = 0x4000
ARENA_START = 0x1010000000
ARENA_END = 0x1100000000


def align(value, alignment):
    return (value + alignment - 1) & -alignment


@dataclass(frozen=True)
class RenderBuffers:
    tilemap: int
    metadata: int
    tpc: int
    tpc_size: int
    end: int

    @property
    def pages(self):
        # Leave one unmapped page between the independently addressed arrays.
        return (*range(self.tilemap, self.tpc - PAGE, PAGE),
                *range(self.tpc, self.end, PAGE))


def render_buffers(params, base):
    """Size one scene from UAPI geometry; no program or attachment inspection."""
    from .g17g_render import _render_geometry
    if (base % PAGE or not ARENA_START <= base < ARENA_END or
            not 1 <= params.width <= 16384 or not 1 <= params.height <= 16384 or
            not 1 <= params.layers <= 2048 or
            (params.utile_width, params.utile_height) not in ((32, 32), (32, 16), (16, 16))):
        raise ValueError("invalid G17G render buffer geometry or base")
    geometry = _render_geometry(params)
    tilemap_size = align(geometry['size1'] * 64 * params.layers, 0x1000)
    metadata = base + tilemap_size
    tpc = align(metadata + 0x200 * params.layers, PAGE) + PAGE
    tpc_size = geometry['size3'] * 4 * 16 * params.layers
    end = tpc + align(tpc_size, PAGE)
    if end > ARENA_END:
        raise MemoryError("G17G render buffers exceed their resource window")
    return RenderBuffers(base, metadata, tpc, tpc_size, end)


def next_render_buffer_base(private_dvas):
    return max((va + PAGE for va in private_dvas if ARENA_START <= va < ARENA_END),
               default=ARENA_START)


def ensure_render_buffers(runtime, params):
    """Back a new scene before publication, retaining every prior allocation."""
    from . import g17g_uat
    if params.buffers is None:
        return
    context = runtime.context
    pages = set(params.buffers.pages)
    if runtime.layout is None and pages & set(context['caller_mappings']):
        raise ValueError("render buffers overlap caller mappings")
    missing = sorted(pages - set(context['pages']))
    if runtime.layout is not None:
        missing = sorted(pages - context.get('private_labels', set()))
    if missing:
        base = runtime.alloc(len(missing) * PAGE)
        context['allocations'].append((base, len(missing) * PAGE))
        physical = [base + index * PAGE for index in range(len(missing))]
        runtime.publish(physical)
        for va, pa in zip(missing, physical):
            context['pages'][va] = pa
            runtime.uat.iomap_at_root(context['root0'], va, pa, PAGE,
                                     **g17g_uat.FLAGS_CONTEXT0_UXN)
        context['table_witnesses'].update(missing)
        context.setdefault('private_labels', set()).update(missing)
        runtime.flush_tables(runtime.context_id)
    runtime.private_dvas.update(pages)
    if runtime.layout is not None:
        runtime.layout.reserve(pages)
        runtime.layout.scene_pages.update(pages)
        runtime.layout.relocate_context(runtime, context, pages=pages)
