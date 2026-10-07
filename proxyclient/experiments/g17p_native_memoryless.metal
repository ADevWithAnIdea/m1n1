// SPDX-License-Identifier: MIT
// One pixel, seven memoryless integer accumulators, one observable sum.
#include <metal_stdlib>
using namespace metal;
struct GrowthVertex { float4 position [[position]]; };
struct GrowthFragment {
    uint sum [[color(0), raster_order_group(0)]];
    uint a [[color(1), raster_order_group(0)]];
    uint b [[color(2), raster_order_group(0)]];
    uint c [[color(3), raster_order_group(0)]];
    uint d [[color(4), raster_order_group(0)]];
    uint e [[color(5), raster_order_group(0)]];
    uint f [[color(6), raster_order_group(0)]];
    uint g [[color(7), raster_order_group(0)]];
};
vertex GrowthVertex growth_vertex(uint id [[vertex_id]]) {
    const float2 corners[3] = {float2(.1, .1), float2(.9, .1), float2(.5, .9)};
    float2 xy = corners[id % 3];
    return {float4(xy.x / 64.0 - 1.0, 1.0 - xy.y / 64.0, 0, 1)};
}
fragment GrowthFragment growth_fragment(
    uint a [[color(1), raster_order_group(0)]],
    uint b [[color(2), raster_order_group(0)]],
    uint c [[color(3), raster_order_group(0)]],
    uint d [[color(4), raster_order_group(0)]],
    uint e [[color(5), raster_order_group(0)]],
    uint f [[color(6), raster_order_group(0)]],
    uint g [[color(7), raster_order_group(0)]]) {
    GrowthFragment out;
    out.a = a + 1; out.b = b + 2; out.c = c + 3; out.d = d + 4;
    out.e = e + 5; out.f = f + 6; out.g = g + 7;
    out.sum = out.a + out.b + out.c + out.d + out.e + out.f + out.g;
    return out;
}
