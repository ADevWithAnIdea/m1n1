# SPDX-License-Identifier: GPL-2.0-only
"""Opaque caller fixtures for UAPI-to-firmware byte comparisons; no hardware setup."""
from dataclasses import replace
import struct
from m1n1.drm_shim import g17g_backend as backend, g17g_modern as modern, g17g_uapi as api
from m1n1.drm_shim import g17g_render as render, g17g_encoder as encoder
PAGE = modern.PAGE_SIZE
STATE_PROBES = {
    'empty-tiles-toggle':dict(),
    'relocated-arrays':dict(scissor_array=0x10000390000,depth_bias_array=0x10000394000),
    'geometry-32x64':dict(width=32,height=64),
    'sampler-one':dict(sampler_array=0x10000398000,sampler_count=1),
    'query-base':dict(occlusion_query_base=0x10000398000),
    'merge-bounds':dict(merge_upper_x_bits=0x3d5db3d9,merge_upper_y_bits=0x3dddb3d9),
    'depth-bias-integer':dict(depth_bias_is_integer=True),
    'relocated-programs':dict(store_pipeline=0x100003a0400,load_pipeline=0x100003a0200),
}

def command_bytes(params, attachments=None, *, extra_flags=0):
    payload = api.drm_asahi_cmd_render()
    payload.flags = (api.DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES if params.process_empty_tiles else 0)
    payload.flags |= extra_flags
    if params.depth_bias_is_integer:
        payload.flags |= api.DRM_ASAHI_RENDER_DBIAS_IS_INT
    payload.vdm_ctrl_stream_base = params.vdm_ctrl_stream_base
    payload.isp_scissor_base = params.resolved_scissor_array()
    payload.isp_dbias_base = params.resolved_depth_bias_array()
    payload.isp_oclqry_base = params.occlusion_query_base
    payload.isp_zls_pixels, payload.zls_ctrl = params.depth_dimensions, params.depth_flags
    for field, prefix in ((payload.depth, "depth"), (payload.stencil, "stencil")):
        field.base = getattr(params, prefix + "_buffer")
        field.comp_base = getattr(params, prefix + "_aux_buffer")
        field.stride = getattr(params, prefix + "_stride")
        field.comp_stride = getattr(params, prefix + "_aux_stride")
    payload.sampler_heap, payload.sampler_count = params.sampler_array, params.sampler_count
    payload.ppp_multisamplectl, payload.ppp_ctrl = params.multisample_control, params.ppp_control
    payload.width_px, payload.height_px, payload.layers = params.width, params.height, params.layers
    payload.utile_width_px, payload.utile_height_px = params.utile_width, params.utile_height
    payload.samples, payload.sample_size_B = params.samples, params.sample_size
    payload.isp_merge_upper_x, payload.isp_merge_upper_y = params.resolved_merge_upper_x_bits(), params.resolved_merge_upper_y_bits()
    for destination, usc, rsrc in ((payload.bg, params.load_pipeline, params.load_pipeline_bind),
            (payload.eot, params.store_pipeline, params.store_pipeline_bind),
            (payload.partial_bg, params.resolved_partial_load_pipeline(), params.partial_load_pipeline_bind),
            (payload.partial_eot, params.resolved_partial_store_pipeline(), params.partial_store_pipeline_bind)):
        destination.usc = usc - modern.USC_EXEC_BASE
        destination.rsrc_spec = rsrc & 0xffffffff
    payload.isp_bgobjdepth, payload.isp_bgobjvals = params.depth_clear_value_bits, params.stencil_clear_value | 0x300
    attachments = ((params.target_dva, PAGE),) if attachments is None else attachments
    attachment_bytes = b"".join(api.drm_asahi_attachment(address, size, 0, 0).to_bytes()
                                for address, size in attachments)
    def part(kind, body):
        return api.drm_asahi_cmd_header(kind, len(body), api.DRM_ASAHI_BARRIER_NONE,
                                        api.DRM_ASAHI_BARRIER_NONE).to_bytes() + body
    return part(api.DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, attachment_bytes) + part(api.DRM_ASAHI_CMD_RENDER, payload.to_bytes())

def caller_case(zls=None, *, state_probe=None):
    products = backend.build_clear_render_products()
    params = products["parameters"]
    expected = {params.target_dva: render.encode_bgra8_unorm_pixel(params.clear_rgba) * (PAGE // 4)}
    if state_probe is not None:
        if zls is not None:
            raise ValueError('state probe requires the ordinary clear caller')
        params = replace(params,**STATE_PROBES[state_probe])
        products = backend.build_clear_render_products(params)
        pixel = render.encode_bgra8_unorm_pixel(params.clear_rgba)
        image = (pixel*params.width+bytes((params.target_stride_pixels-params.width)*4))*params.height
        expected[params.target_dva] = image.ljust(PAGE,b'\0')
        if params.occlusion_query_base:
            expected[params.occlusion_query_base] = bytes([0xa5])*PAGE
        if params.sampler_count:
            expected[params.sampler_array] = bytes(PAGE)
        return products,expected
    geometry = {
        'layers3':dict(layers=3,samples=1,utile_width=32,utile_height=32,multisample_control=0x88,depth_stride=1,stencil_stride=1),
        'msaa2':dict(layers=1,samples=2,utile_width=32,utile_height=32,multisample_control=0x44cc,depth_stride=0,stencil_stride=0),
        'msaa4':dict(layers=1,samples=4,utile_width=32,utile_height=16,multisample_control=0xeaa26e26,depth_stride=0,stencil_stride=0),
    }.get(zls)
    if geometry is not None:
        params = replace(params,**geometry,sample_size=8,
            depth_buffer=backend.RENDER_ZLS_DEPTH_DVA,stencil_buffer=backend.RENDER_ZLS_STENCIL_ARRAY_DVA,
            depth_dimensions=render.encode_zls_dimensions(params.width,params.height),
            depth_clear_value_bits=0x3e800000,stencil_clear_value=0x5a,
            depth_flags=render.ZLS_STORE_DEPTH | render.ZLS_STORE_STENCIL)
        products = backend.build_clear_render_products(params)
        if zls == 'msaa4':
            # This own diagnostic EOT writes a64x16 color witness; fixed-function
            # ZLS covers all four full64x64 sample planes independently.
            prefix = render.encode_bgra8_unorm_pixel(params.clear_rgba)*params.target_stride_pixels*params.utile_height
            expected[params.target_dva] = prefix+bytes(PAGE-len(prefix))
        planes = max(params.layers,params.samples)
        depth = struct.pack('<I',params.depth_clear_value_bits)*(PAGE//4)*planes
        stencil = ((bytes([params.stencil_clear_value])*(PAGE//4)+bytes(3*PAGE//4))*planes
                   if params.layers>1 else
                   bytes([params.stencil_clear_value])*(PAGE//4)*planes+bytes(3*PAGE//4)*planes)
        for base,image in ((params.depth_buffer,depth),(params.stencil_buffer,stencil)):
            expected.update((base+offset,image[offset:offset+PAGE]) for offset in range(0,len(image),PAGE))
        return products,expected
    if zls:
        params = replace(params, depth_buffer=backend.RENDER_ZLS_DEPTH_DVA,
            stencil_buffer=backend.RENDER_ZLS_STENCIL_DVA,
            depth_dimensions=render.encode_zls_dimensions(params.width, params.height),
            depth_clear_value_bits=0x3e800000, stencil_clear_value=0x5a,
            depth_flags=render.ZLS_STORE_DEPTH | render.ZLS_STORE_STENCIL)
        initial = None
        if zls == "load-store":
            params = replace(params, depth_flags=params.depth_flags | render.ZLS_LOAD_DEPTH | render.ZLS_LOAD_STENCIL)
            initial = dict(depth=struct.pack("<I", 0x3f400000) * (PAGE // 4),
                           stencil=bytes([0x7b]) * (PAGE // 4) + bytes(3 * PAGE // 4))
        elif zls != "store":
            raise ValueError("unknown caller ZLS case")
        products = backend.build_clear_render_products(params, zls_initial=initial)
        expected[params.depth_buffer] = initial["depth"] if initial else struct.pack("<I", params.depth_clear_value_bits) * (PAGE // 4)
        expected[params.stencil_buffer] = initial["stencil"] if initial else bytes([params.stencil_clear_value]) * (PAGE // 4) + bytes(3 * PAGE // 4)
    return products, expected

def caller_vdm_page(params, vertices):
    """Rebuild only the caller stream, not an entire reference submission."""
    body = encoder.build_direct_vdm_page(encoder.G17GDirectDraw(vertex_count=vertices))
    size, offset = encoder.direct_vdm_stream_size(), params.vdm_ctrl_stream_base % PAGE
    if offset + size > PAGE:
        raise ValueError("partial smoke caller stream crosses its owned page")
    return bytes(offset) + body[:size] + bytes(PAGE - offset - size)
