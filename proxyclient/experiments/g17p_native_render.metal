// SPDX-License-Identifier: MIT
#include <metal_stdlib>

using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float4 varying0;
    float4 varying1;
    float4 varying2;
    float4 varying3;
    float4 varying4;
    float4 varying5;
    float4 varying6;
    float4 varying7;
};

vertex VertexOut vertex_main(uint id [[vertex_id]])
{
    const float2 corners[3] = {
        float2(0.1, 0.1),
        float2(0.9, 0.1),
        float2(0.5, 0.9),
    };
    uint triangle = id / 3;
    uint pixel = triangle % (128 * 37);
    float2 point = float2(pixel % 128, pixel / 128) + corners[id % 3];
    VertexOut out;
    out.position = float4(
        point.x * (2.0 / 128.0) - 1.0,
        point.y * (2.0 / 37.0) - 1.0,
        0.0, 1.0);
    const float4 part = float4(0.03125, 0.0625, 0.09375, 0.125);
    out.varying0 = part;
    out.varying1 = part;
    out.varying2 = part;
    out.varying3 = part;
    out.varying4 = part;
    out.varying5 = part;
    out.varying6 = part;
    out.varying7 = part;
    return out;
}

fragment float4 fragment_main(VertexOut in [[stage_in]])
{
    return in.varying0 + in.varying1 + in.varying2 + in.varying3
         + in.varying4 + in.varying5 + in.varying6 + in.varying7;
}
