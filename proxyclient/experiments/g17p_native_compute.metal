// SPDX-License-Identifier: MIT

#include <metal_stdlib>
using namespace metal;

kernel void g17p_add(device const float *a [[buffer(0)]],
                     device const float *b [[buffer(1)]],
                     device float *out [[buffer(2)]],
                     uint index [[thread_position_in_grid]])
{
    out[index] = a[index] + b[index];
}

struct g17p_sampler_heap4 {
    array<sampler, 4> samplers;
};

kernel void g17p_sampler_heap(
                     device const float *a [[buffer(0)]],
                     device const float *b [[buffer(1)]],
                     device float *out [[buffer(2)]],
                     constant g17p_sampler_heap4& heap [[buffer(3)]],
                     texture2d<float> texture [[texture(0)]],
                     uint index [[thread_position_in_grid]])
{
    float sampled = texture.sample(
        heap.samplers[index & 3], float2(0.5f, 0.5f)).x;
    out[index] = a[index] + b[index] + sampled;
}

kernel void g17p_command_sampler(
                     device const float *a [[buffer(0)]],
                     device const float *b [[buffer(1)]],
                     device float *out [[buffer(2)]],
                     texture2d<float> texture [[texture(0)]],
                     sampler sample_state [[sampler(0)]],
                     uint index [[thread_position_in_grid]])
{
    float sampled = texture.sample(sample_state, float2(0.5f, 0.5f)).x;
    out[index] = a[index] + b[index] + sampled;
}

kernel void g17p_spill(device const float *a [[buffer(0)]],
                       device const float *b [[buffer(1)]],
                       device float *out [[buffer(2)]],
                       uint index [[thread_position_in_grid]])
{
    volatile float values[1024];
    for (uint element = 0; element < 1024; element++)
        values[element] = a[index] + b[index] * float(element);

    float sum = 0.0f;
    uint rotation = (index * 17) & 1023;
    for (uint element = 0; element < 1024; element++)
        sum += values[(element + rotation) & 1023];
    out[index] = sum;
}

kernel void g17p_grid_setup(device const uint *threadgroups [[buffer(0)]],
                            device const uint *threads_per_group [[buffer(1)]],
                            device uint *geometry [[buffer(2)]],
                            uint index [[thread_position_in_grid]])
{
    if (index != 0)
        return;

    geometry[0] = threadgroups[0] * threads_per_group[0];
    geometry[1] = threadgroups[1] * threads_per_group[1];
    geometry[2] = threadgroups[2] * threads_per_group[2];
    geometry[3] = threads_per_group[0];
    geometry[4] = threads_per_group[1];
    geometry[5] = threads_per_group[2];
}
