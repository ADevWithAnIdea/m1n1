// SPDX-License-Identifier: MIT
// Own-source Metal compute workload for the T8140/G17P trace.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>


static const char *METALLIB_PATH =
    "/System/Volumes/Data/Users/Shared/g17pcmp.metallib";
static const size_t BUFFER_SIZE = 0x4000;
static const size_t ELEMENTS = 64;


static void print_va(const char *label, uint64_t va)
{
    printf("VA %-6s = 0x%016llx\n", label, (unsigned long long)va);
}


int main(int argc, const char *argv[])
{
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);

        unsigned long dispatch_count = 1;
        unsigned long pause_before = ULONG_MAX;
        BOOL sequential = NO;
        BOOL hold_after = NO;
        BOOL indirect = NO;
        BOOL grid_helper = NO;
        BOOL sampler_heap = NO;
        BOOL command_sampler = NO;
        BOOL spill = NO;
        BOOL resource_hint = NO;
        BOOL warmup = NO;
        if (argc > 1) {
            char *end = NULL;
            dispatch_count = strtoul(argv[1], &end, 0);
            if (end == argv[1] || *end != '\0' || dispatch_count == 0) {
                printf("G17P_COMPUTE_COUNT_FAIL %s\n", argv[1]);
                return 6;
            }
        }
        if (argc > 2) {
            if (strcmp(argv[2], "sequential") == 0) {
                sequential = YES;
            } else {
                char *end = NULL;
                pause_before = strtoul(argv[2], &end, 0);
                if (end == argv[2] || *end != '\0' ||
                    pause_before >= dispatch_count) {
                    printf("G17P_COMPUTE_PAUSE_FAIL %s\n", argv[2]);
                    return 7;
                }
            }
        }
        if (argc > 3) {
            if (strcmp(argv[3], "hold") != 0) {
                printf("G17P_COMPUTE_HOLD_FAIL %s\n", argv[3]);
                return 8;
            }
            hold_after = YES;
        }
        if (argc > 4) {
            if (strcmp(argv[4], "indirect") == 0) {
                indirect = YES;
            } else if (strcmp(argv[4], "gridhelper") == 0) {
                grid_helper = YES;
            } else if (strcmp(argv[4], "samplerheap") == 0) {
                sampler_heap = YES;
            } else if (strcmp(argv[4], "commandsampler") == 0) {
                command_sampler = YES;
            } else if (strcmp(argv[4], "spill") == 0) {
                spill = YES;
            } else if (strcmp(argv[4], "resourcehint") == 0) {
                resource_hint = YES;
            } else {
                printf("G17P_COMPUTE_MODE_FAIL %s\n", argv[4]);
                return 9;
            }
        }
        if (argc > 5) {
            if (strcmp(argv[5], "warmup") != 0) {
                printf("G17P_COMPUTE_WARMUP_FAIL %s\n", argv[5]);
                return 10;
            }
            warmup = YES;
        }

        id<MTLDevice> device = nil;
        for (unsigned int attempt = 0; attempt < 1800; attempt++) {
            device = MTLCreateSystemDefaultDevice();
            if (device != nil)
                break;
            usleep(100000);
        }
        if (device == nil) {
            printf("G17P_COMPUTE_DEVICE_FAIL\n");
            return 1;
        }
        printf("G17P_COMPUTE_DEVICE %s\n", [[device name] UTF8String]);

        NSError *error = nil;
        NSURL *url = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:METALLIB_PATH]];
        id<MTLLibrary> library = [device newLibraryWithURL:url error:&error];
        if (library == nil) {
            printf("G17P_COMPUTE_LIBRARY_FAIL %s\n",
                   [[error localizedDescription] UTF8String]);
            return 2;
        }
        NSString *function_name = grid_helper ? @"g17p_grid_setup" :
            (sampler_heap ? @"g17p_sampler_heap" :
             (command_sampler ? @"g17p_command_sampler" :
              (spill ? @"g17p_spill" : @"g17p_add")));
        id<MTLFunction> function = [library newFunctionWithName:function_name];
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:function error:&error];
        if (pipeline == nil) {
            printf("G17P_COMPUTE_PIPELINE_FAIL %s\n",
                   [[error localizedDescription] UTF8String]);
            return 3;
        }
        MTLResourceOptions options = MTLResourceStorageModeShared;
        id<MTLBuffer> buffer_a =
            [device newBufferWithLength:BUFFER_SIZE options:options];
        id<MTLBuffer> buffer_b =
            [device newBufferWithLength:BUFFER_SIZE options:options];
        id<MTLBuffer> indirect_args = nil;
        if (indirect) {
            indirect_args =
                [device newBufferWithLength:BUFFER_SIZE options:options];
        }
        if (buffer_a == nil || buffer_b == nil ||
            (indirect && indirect_args == nil)) {
            printf("G17P_COMPUTE_BUFFER_FAIL\n");
            return 4;
        }

        memset([buffer_a contents], 0, BUFFER_SIZE);
        memset([buffer_b contents], 0, BUFFER_SIZE);
        if (grid_helper) {
            uint32_t *threadgroups = [buffer_a contents];
            uint32_t *threads_per_group = [buffer_b contents];
            threadgroups[0] = 2;
            threadgroups[1] = 1;
            threadgroups[2] = 1;
            threads_per_group[0] = 32;
            threads_per_group[1] = 1;
            threads_per_group[2] = 1;
        } else {
            float *a = [buffer_a contents];
            float *b = [buffer_b contents];
            for (size_t index = 0; index < ELEMENTS; index++) {
                a[index] = 1000.0f + (float)index;
                b[index] = 0.5f;
            }
        }

        print_va("bufA", [buffer_a gpuAddress]);
        print_va("bufB", [buffer_b gpuAddress]);
        if (indirect) {
            uint32_t *args = [indirect_args contents];
            memset(args, 0, BUFFER_SIZE);
            args[0] = 2;
            args[1] = 1;
            args[2] = 1;
            print_va("indArg", [indirect_args gpuAddress]);
        }

        id<MTLBuffer> sampler_heap_buffer = nil;
        id<MTLTexture> sampler_texture = nil;
        NSMutableArray<id<MTLSamplerState>> *samplers = nil;
        if (sampler_heap || command_sampler) {
            id<MTLArgumentEncoder> argument_encoder = nil;
            if (sampler_heap) {
                argument_encoder =
                    [function newArgumentEncoderWithBufferIndex:3];
                sampler_heap_buffer = [device
                    newBufferWithLength:[argument_encoder encodedLength]
                    options:options];
                [argument_encoder
                    setArgumentBuffer:sampler_heap_buffer offset:0];
            }
            samplers = [NSMutableArray arrayWithCapacity:4];
            NSUInteger sampler_count = sampler_heap ? 4 : 1;
            for (NSUInteger index = 0; index < sampler_count; index++) {
                MTLSamplerDescriptor *descriptor =
                    [[MTLSamplerDescriptor alloc] init];
                descriptor.supportArgumentBuffers = sampler_heap;
                descriptor.minFilter = command_sampler ?
                    MTLSamplerMinMagFilterLinear : (index & 1) ?
                    MTLSamplerMinMagFilterLinear :
                    MTLSamplerMinMagFilterNearest;
                descriptor.magFilter = descriptor.minFilter;
                id<MTLSamplerState> state =
                    [device newSamplerStateWithDescriptor:descriptor];
                if (state == nil) {
                    printf("G17P_COMPUTE_SAMPLER_FAIL %lu\n",
                           (unsigned long)index);
                    return 12;
                }
                [samplers addObject:state];
                if (sampler_heap)
                    [argument_encoder setSamplerState:state atIndex:index];
            }

            MTLTextureDescriptor *texture_descriptor =
                [MTLTextureDescriptor
                    texture2DDescriptorWithPixelFormat:MTLPixelFormatR32Float
                    width:2 height:2 mipmapped:NO];
            texture_descriptor.storageMode = MTLStorageModeShared;
            texture_descriptor.usage = MTLTextureUsageShaderRead;
            sampler_texture = [device newTextureWithDescriptor:texture_descriptor];
            if ((sampler_heap && sampler_heap_buffer == nil) ||
                    sampler_texture == nil) {
                printf("G17P_COMPUTE_SAMPLER_RESOURCE_FAIL\n");
                return 13;
            }
            static const float texture_rows[2][2] = {
                {0.0f, 1.0f}, {2.0f, 3.0f},
            };
            for (NSUInteger row = 0; row < 2; row++) {
                [sampler_texture replaceRegion:MTLRegionMake2D(0, row, 2, 1)
                    mipmapLevel:0 withBytes:texture_rows[row] bytesPerRow:8];
            }
            if (sampler_heap)
                print_va("sampHp", [sampler_heap_buffer gpuAddress]);
            printf("G17P_COMPUTE_SAMPLER_IDS");
            for (id<MTLSamplerState> state in samplers)
                printf(" %llu", (unsigned long long)state.gpuResourceID._impl);
            printf("\n");
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (warmup) {
            id<MTLBuffer> warmup_output =
                [device newBufferWithLength:BUFFER_SIZE options:options];
            if (warmup_output == nil) {
                printf("G17P_COMPUTE_WARMUP_BUFFER_FAIL\n");
                return 4;
            }
            memset([warmup_output contents], 0x5a, BUFFER_SIZE);
            id<MTLCommandBuffer> warmup_command = [queue commandBuffer];
            id<MTLComputeCommandEncoder> warmup_encoder =
                [warmup_command computeCommandEncoder];
            [warmup_encoder setComputePipelineState:pipeline];
            [warmup_encoder setBuffer:buffer_a offset:0 atIndex:0];
            [warmup_encoder setBuffer:buffer_b offset:0 atIndex:1];
            [warmup_encoder setBuffer:warmup_output offset:0 atIndex:2];
            [warmup_encoder dispatchThreads:MTLSizeMake(ELEMENTS, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
            [warmup_encoder endEncoding];
            printf("G17P_COMPUTE_WARMUP_COMMIT\n");
            [warmup_command commit];
            [warmup_command waitUntilCompleted];
            printf("G17P_COMPUTE_WARMUP_STATUS %ld\n",
                   (long)[warmup_command status]);
            if ([warmup_command status] != MTLCommandBufferStatusCompleted)
                return 11;
        }
        NSMutableArray<id<MTLBuffer>> *outputs =
            [NSMutableArray arrayWithCapacity:dispatch_count];
        NSMutableArray<id<MTLCommandBuffer>> *commands =
            [NSMutableArray arrayWithCapacity:dispatch_count];
        BOOL exact = YES;

        // Publish every command before waiting. This exposes the second queue
        // transition even when a traced guest delays first-command completion.
        for (unsigned long dispatch = 0; dispatch < dispatch_count; dispatch++) {
            if (dispatch == pause_before) {
                printf("G17P_COMPUTE_PAUSED_BEFORE %lu\n", dispatch);
                raise(SIGSTOP);
                printf("G17P_COMPUTE_RESUMED_BEFORE %lu\n", dispatch);
            }
            id<MTLBuffer> output =
                [device newBufferWithLength:BUFFER_SIZE options:options];
            if (output == nil) {
                printf("G17P_COMPUTE_BUFFER_FAIL %lu\n", dispatch);
                return 4;
            }
            memset([output contents], 0, BUFFER_SIZE);
            if (!sequential)
                [outputs addObject:output];
            printf("VA bufOut%lu = 0x%016llx\n", dispatch,
                   (unsigned long long)[output gpuAddress]);

            id<MTLCommandBuffer> command = [queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:buffer_a offset:0 atIndex:0];
            [encoder setBuffer:buffer_b offset:0 atIndex:1];
            [encoder setBuffer:output offset:0 atIndex:2];
            if (resource_hint)
                [encoder useResource:output usage:MTLResourceUsageWrite];
            if (sampler_heap || command_sampler) {
                if (sampler_heap)
                    [encoder setBuffer:sampler_heap_buffer offset:0 atIndex:3];
                [encoder setTexture:sampler_texture atIndex:0];
                if (command_sampler)
                    [encoder setSamplerState:samplers[0] atIndex:0];
            }
            if (indirect) {
                [encoder dispatchThreadgroupsWithIndirectBuffer:indirect_args
                    indirectBufferOffset:0
                    threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
            } else if (grid_helper) {
                [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
                      threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
            } else {
                [encoder dispatchThreads:MTLSizeMake(ELEMENTS, 1, 1)
                      threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
            }
            [encoder endEncoding];

            printf("G17P_COMPUTE_COMMIT %lu\n", dispatch);
            [command commit];
            if (!sequential)
                [commands addObject:command];

            if (sequential) {
                float *out = [output contents];
                [command waitUntilCompleted];
                printf("G17P_COMPUTE_STATUS %lu %ld\n",
                       dispatch, (long)[command status]);
                if ([command error] != nil)
                    printf("G17P_COMPUTE_ERROR %lu %s\n", dispatch,
                           [[[command error] localizedDescription] UTF8String]);
                printf("G17P_COMPUTE_OUTPUT_AFTER %lu %08x %08x\n", dispatch,
                       ((unsigned int *)out)[0], ((unsigned int *)out)[1]);
                if (grid_helper) {
                    uint32_t *geometry = [output contents];
                    printf("G17P_GRID_HELPER_RESULT %lu %u %u %u %u %u %u\n",
                           dispatch, geometry[0], geometry[1], geometry[2],
                           geometry[3], geometry[4], geometry[5]);
                } else if (sampler_heap || command_sampler) {
                    printf("G17P_COMPUTE_SAMPLER_RESULT %lu %.1f %.1f\n",
                           dispatch, out[0], out[1]);
                } else {
                    printf("G17P_COMPUTE_RESULT %lu %.1f %.1f\n",
                           dispatch, out[0], out[1]);
                }

                BOOL dispatch_exact =
                    [command status] == MTLCommandBufferStatusCompleted;
                if (grid_helper) {
                    static const uint32_t expected[] = {64, 1, 1, 32, 1, 1};
                    dispatch_exact &= memcmp([output contents], expected,
                                             sizeof(expected)) == 0;
                } else if (sampler_heap) {
                    for (size_t index = 0; index < ELEMENTS; index++) {
                        float sampled = (index & 1) ? 1.5f : 3.0f;
                        dispatch_exact &= out[index] ==
                            1000.5f + (float)index + sampled;
                    }
                } else if (command_sampler) {
                    for (size_t index = 0; index < ELEMENTS; index++)
                        dispatch_exact &= out[index] == 1002.0f + (float)index;
                } else if (spill) {
                    for (size_t index = 0; index < ELEMENTS; index++)
                        dispatch_exact &= out[index] ==
                            1285888.0f + 1024.0f * (float)index;
                } else {
                    for (size_t index = 0; index < ELEMENTS; index++)
                        dispatch_exact &= out[index] == 1000.5f + (float)index;
                }
                printf("G17P_COMPUTE_EXACT %lu %d\n",
                       dispatch, dispatch_exact ? 1 : 0);
                exact &= dispatch_exact;
            }
        }

        for (unsigned long dispatch = 0;
             !sequential && dispatch < dispatch_count; dispatch++) {
            id<MTLCommandBuffer> command = commands[dispatch];
            float *out = [outputs[dispatch] contents];
            [command waitUntilCompleted];
            printf("G17P_COMPUTE_STATUS %lu %ld\n",
                   dispatch, (long)[command status]);
            if ([command error] != nil)
                printf("G17P_COMPUTE_ERROR %lu %s\n", dispatch,
                       [[[command error] localizedDescription] UTF8String]);
            printf("G17P_COMPUTE_OUTPUT_AFTER %lu %08x %08x\n", dispatch,
                   ((unsigned int *)out)[0], ((unsigned int *)out)[1]);
            if (grid_helper) {
                uint32_t *geometry = [outputs[dispatch] contents];
                printf("G17P_GRID_HELPER_RESULT %lu %u %u %u %u %u %u\n",
                       dispatch, geometry[0], geometry[1], geometry[2],
                       geometry[3], geometry[4], geometry[5]);
            } else if (sampler_heap || command_sampler) {
                printf("G17P_COMPUTE_SAMPLER_RESULT %lu %.1f %.1f\n",
                       dispatch, out[0], out[1]);
            } else {
                printf("G17P_COMPUTE_RESULT %lu %.1f %.1f\n",
                       dispatch, out[0], out[1]);
            }

            BOOL dispatch_exact =
                [command status] == MTLCommandBufferStatusCompleted;
            if (grid_helper) {
                static const uint32_t expected[] = {64, 1, 1, 32, 1, 1};
                dispatch_exact &= memcmp([outputs[dispatch] contents], expected,
                                         sizeof(expected)) == 0;
            } else if (sampler_heap) {
                for (size_t index = 0; index < ELEMENTS; index++) {
                    float sampled = (index & 1) ? 1.5f : 3.0f;
                    dispatch_exact &= out[index] ==
                        1000.5f + (float)index + sampled;
                }
            } else if (command_sampler) {
                for (size_t index = 0; index < ELEMENTS; index++)
                    dispatch_exact &= out[index] == 1002.0f + (float)index;
            } else if (spill) {
                for (size_t index = 0; index < ELEMENTS; index++)
                    dispatch_exact &= out[index] ==
                        1285888.0f + 1024.0f * (float)index;
            } else {
                for (size_t index = 0; index < ELEMENTS; index++)
                    dispatch_exact &= out[index] == 1000.5f + (float)index;
            }
            printf("G17P_COMPUTE_EXACT %lu %d\n",
                   dispatch, dispatch_exact ? 1 : 0);
            exact &= dispatch_exact;
        }
        printf("G17P_COMPUTE_ALL_EXACT %lu %d\n",
               dispatch_count, exact ? 1 : 0);
        if (hold_after) {
            printf("G17P_COMPUTE_HOLDING\n");
            raise(SIGSTOP);
        }
        return exact ? 0 : 5;
    }
}
