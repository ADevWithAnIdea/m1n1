// SPDX-License-Identifier: MIT
#include <metal_stdlib>

using namespace metal;

struct BarrierVertex {
    float4 position [[position]];
};

kernel void barrier_make_vertices(device float4 *positions [[buffer(0)]],
                                  uint index [[thread_position_in_grid]])
{
    const float4 triangle[3] = {
        float4(-1.0, -1.0, 0.0, 1.0),
        float4( 3.0, -1.0, 0.0, 1.0),
        float4(-1.0,  3.0, 0.0, 1.0),
    };
    if (index < 3)
        positions[index] = triangle[index];
}

vertex BarrierVertex barrier_vertex(device const float4 *positions [[buffer(0)]],
                                    uint index [[vertex_id]])
{
    BarrierVertex out;
    out.position = positions[index];
    return out;
}

fragment float4 barrier_fragment()
{
    return float4(0.25, 0.5, 0.75, 1.0);
}

kernel void barrier_read_texture(texture2d<float, access::read> source [[texture(0)]],
                                 device float4 *output [[buffer(0)]],
                                 uint2 position [[thread_position_in_grid]])
{
    if (position.x < source.get_width() && position.y < source.get_height())
        output[position.y * source.get_width() + position.x] =
            source.read(position);
}
