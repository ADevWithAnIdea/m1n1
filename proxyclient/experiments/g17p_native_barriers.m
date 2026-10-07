// SPDX-License-Identifier: MIT
// Minimal compute -> render -> compute dependency witness for T8140/G17P.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static NSString *const source_path =
    @"/System/Volumes/Data/Users/Shared/g17pbarrier/g17pbarrier.metal";

static FILE *open_console(void)
{
    FILE *console = fopen("/dev/console", "w");
    if (console != NULL)
        setvbuf(console, NULL, _IONBF, 0);
    return console;
}

static BOOL exact4(const float *value, float a, float b, float c, float d)
{
    return value[0] == a && value[1] == b && value[2] == c && value[3] == d;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        BOOL encoder_fences = argc == 2 && strcmp(argv[1], "--fences") == 0;
        BOOL consumer_first = argc == 2 && strcmp(argv[1], "--gpu-event-reverse") == 0;
        BOOL gpu_event = consumer_first ||
            (argc == 2 && strcmp(argv[1], "--gpu-event") == 0);
        if (argc > 1 && !encoder_fences && !gpu_event)
            return 64;
        enum { width = 4, height = 4, pixels = width * height };
        NSError *error = nil;
        FILE *console = open_console();
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil)
            return 1;
        NSString *source = [NSString stringWithContentsOfFile:source_path
            encoding:NSUTF8StringEncoding error:&error];
        id<MTLLibrary> library = source == nil ? nil :
            [device newLibraryWithSource:source options:nil error:&error];
        if (library == nil) {
            fprintf(console, "G17P_BARRIER_ERROR library %s\n",
                    [[error localizedDescription] UTF8String]);
            return 2;
        }

        id<MTLComputePipelineState> make_vertices = [device
            newComputePipelineStateWithFunction:
                [library newFunctionWithName:@"barrier_make_vertices"]
            error:&error];
        id<MTLComputePipelineState> read_texture = [device
            newComputePipelineStateWithFunction:
                [library newFunctionWithName:@"barrier_read_texture"]
            error:&error];
        MTLRenderPipelineDescriptor *render_desc =
            [[MTLRenderPipelineDescriptor alloc] init];
        render_desc.vertexFunction =
            [library newFunctionWithName:@"barrier_vertex"];
        render_desc.fragmentFunction =
            [library newFunctionWithName:@"barrier_fragment"];
        render_desc.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA32Float;
        id<MTLRenderPipelineState> render = [device
            newRenderPipelineStateWithDescriptor:render_desc error:&error];
        if (make_vertices == nil || read_texture == nil || render == nil) {
            fprintf(console, "G17P_BARRIER_ERROR pipeline %s\n",
                    [[error localizedDescription] UTF8String]);
            return 3;
        }

        id<MTLBuffer> positions = [device
            newBufferWithLength:3 * 4 * sizeof(float)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> texture_storage = [device
            newBufferWithLength:pixels * 4 * sizeof(float)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> result = [device
            newBufferWithLength:pixels * 4 * sizeof(float)
            options:MTLResourceStorageModeShared];
        memset([positions contents], 0, [positions length]);
        memset([texture_storage contents], 0, [texture_storage length]);
        memset([result contents], 0, [result length]);

        MTLTextureDescriptor *texture_desc = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA32Float
                                         width:width height:height mipmapped:NO];
        texture_desc.storageMode = MTLStorageModeShared;
        texture_desc.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
        id<MTLTexture> texture = [texture_storage
            newTextureWithDescriptor:texture_desc offset:0
            bytesPerRow:width * 4 * sizeof(float)];
        id<MTLEvent> event = gpu_event ? [device newEvent] : [device newSharedEvent];
        id<MTLFence> compute_done = [device newFence];
        id<MTLFence> render_done = [device newFence];
        id<MTLCommandQueue> first_queue = [device newCommandQueue];
        id<MTLCommandQueue> middle_queue = [device newCommandQueue];
        id<MTLCommandQueue> last_queue = [device newCommandQueue];
        id<MTLCommandBuffer> first_command = [first_queue commandBuffer];
        id<MTLCommandBuffer> middle_command = encoder_fences ? first_command :
            [middle_queue commandBuffer];
        id<MTLCommandBuffer> last_command = encoder_fences ? first_command :
            [last_queue commandBuffer];
        if (!gpu_event)
            ((id<MTLSharedEvent>)event).signaledValue = 0;

        id<MTLComputeCommandEncoder> first =
            [first_command computeCommandEncoder];
        [first setComputePipelineState:make_vertices];
        [first setBuffer:positions offset:0 atIndex:0];
        [first dispatchThreads:MTLSizeMake(3, 1, 1)
            threadsPerThreadgroup:MTLSizeMake(3, 1, 1)];
        if (encoder_fences)
            [first updateFence:compute_done];
        [first endEncoding];
        if (!encoder_fences)
            [first_command encodeSignalEvent:event value:1];

        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor
            renderPassDescriptor];
        pass.colorAttachments[0].texture = texture;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 0);
        if (!encoder_fences)
            [middle_command encodeWaitForEvent:event value:1];
        id<MTLRenderCommandEncoder> middle =
            [middle_command renderCommandEncoderWithDescriptor:pass];
        if (encoder_fences)
            [middle waitForFence:compute_done beforeStages:MTLRenderStageVertex];
        [middle setRenderPipelineState:render];
        [middle setVertexBuffer:positions offset:0 atIndex:0];
        [middle drawPrimitives:MTLPrimitiveTypeTriangle
                     vertexStart:0 vertexCount:3];
        if (encoder_fences)
            [middle updateFence:render_done afterStages:MTLRenderStageFragment];
        [middle endEncoding];
        if (!encoder_fences)
            [middle_command encodeSignalEvent:event value:2];

        if (!encoder_fences)
            [last_command encodeWaitForEvent:event value:2];
        id<MTLComputeCommandEncoder> last =
            [last_command computeCommandEncoder];
        if (encoder_fences)
            [last waitForFence:render_done];
        [last setComputePipelineState:read_texture];
        [last setTexture:texture atIndex:0];
        [last setBuffer:result offset:0 atIndex:0];
        [last dispatchThreads:MTLSizeMake(width, height, 1)
            threadsPerThreadgroup:MTLSizeMake(width, height, 1)];
        [last endEncoding];

        fprintf(console,
                "G17P_BARRIER_READY pid=%d positions=0x%llx texture=0x%llx "
                "result=0x%llx size=0x%lx mode=%s\n", getpid(),
                (unsigned long long)[positions gpuAddress],
                (unsigned long long)[texture_storage gpuAddress],
                (unsigned long long)[result gpuAddress],
                (unsigned long)[result length], encoder_fences ? "fences" :
                    consumer_first ? "gpu-event-reverse" :
                    gpu_event ? "gpu-event" : "shared-event");
        if (consumer_first) {
            [last_command commit];
            [middle_command commit];
            [first_command commit];
        } else {
            [first_command commit];
            if (!encoder_fences) {
                [middle_command commit];
                [last_command commit];
            }
        }
        [last_command waitUntilCompleted];
        [middle_command waitUntilCompleted];
        [first_command waitUntilCompleted];

        const float *position_values = [positions contents];
        const float *texture_values = [texture_storage contents];
        const float *result_values = [result contents];
        const float expected_positions[12] = {
            -1, -1, 0, 1, 3, -1, 0, 1, -1, 3, 0, 1,
        };
        BOOL positions_exact = memcmp(position_values, expected_positions,
                                      sizeof(expected_positions)) == 0;
        NSUInteger texture_exact = 0, result_exact = 0;
        for (NSUInteger index = 0; index < pixels; ++index) {
            texture_exact += exact4(texture_values + 4 * index,
                                    0.25, 0.5, 0.75, 1.0);
            result_exact += exact4(result_values + 4 * index,
                                   0.25, 0.5, 0.75, 1.0);
        }
        fprintf(console,
                "G17P_BARRIER_DONE status=%ld/%ld/%ld positions=%d texture=%lu/%d "
                "result=%lu/%d error=%s\n", (long)[first_command status],
                (long)[middle_command status], (long)[last_command status],
                positions_exact, (unsigned long)texture_exact, pixels,
                (unsigned long)result_exact, pixels,
                [last_command error] ? [[[last_command error] localizedDescription]
                    UTF8String] : "none");
        return ([first_command status] == MTLCommandBufferStatusCompleted &&
                [middle_command status] == MTLCommandBufferStatusCompleted &&
                [last_command status] == MTLCommandBufferStatusCompleted &&
                positions_exact && texture_exact == pixels &&
                result_exact == pixels) ? 0 : 4;
    }
}
