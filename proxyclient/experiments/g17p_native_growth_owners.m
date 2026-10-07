// SPDX-License-Identifier: MIT
// Two retained queues/pools, independent outputs, one or two pressure draws.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char **argv)
{
    @autoreleasepool {
        if (argc != 4 || (strcmp(argv[3], "memoryless") && strcmp(argv[3], "memoryless-both"))) return 1;
        BOOL both = !strcmp(argv[3], "memoryless-both");
        char *end = NULL;
        NSUInteger pressure = strtoul(argv[2], &end, 10);
        if (!*argv[2] || *end || !pressure || pressure > 1000000) return 1;
        FILE *console = fopen("/dev/console", "w");
        if (!console) return 2;
        setvbuf(console, NULL, _IONBF, 0);
        NSError *error = nil;
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        NSString *source = [NSString stringWithContentsOfFile:@(argv[1])
            encoding:NSUTF8StringEncoding error:&error];
        id<MTLLibrary> library = source ? [device newLibraryWithSource:source
            options:nil error:&error] : nil;
        MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
        pd.vertexFunction = [library newFunctionWithName:@"growth_vertex"];
        pd.fragmentFunction = [library newFunctionWithName:@"growth_fragment"];
        for (NSUInteger i = 0; i < 8; i++)
            pd.colorAttachments[i].pixelFormat = MTLPixelFormatR32Uint;
        id<MTLRenderPipelineState> pipeline = library ?
            [device newRenderPipelineStateWithDescriptor:pd error:&error] : nil;
        if (!pipeline) {
            fprintf(console, "NEO_GROWTH_ERROR pipeline=%s\n", error.description.UTF8String);
            return 3;
        }
        const NSUInteger bytes = 128 * 128 * 4;
        NSMutableArray<id<MTLCommandQueue>> *queues = [NSMutableArray new];
        NSMutableArray<id<MTLBuffer>> *outputs = [NSMutableArray new];
        NSMutableArray<MTLRenderPassDescriptor *> *passes = [NSMutableArray new];
        for (NSUInteger owner = 0; owner < 2; owner++) {
            id<MTLCommandQueue> queue = [device newCommandQueue];
            id<MTLBuffer> output = [device newBufferWithLength:bytes
                options:MTLResourceStorageModeShared];
            if (!queue || !output) return 4;
            memset(output.contents, 0xa5, bytes);
            [queues addObject:queue];
            [outputs addObject:output];
            MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
            for (NSUInteger i = 0; i < 8; i++) {
                MTLTextureDescriptor *td = [MTLTextureDescriptor
                    texture2DDescriptorWithPixelFormat:MTLPixelFormatR32Uint
                    width:128 height:128 mipmapped:NO];
                td.usage = MTLTextureUsageRenderTarget;
                td.storageMode = i ? MTLStorageModeMemoryless : MTLStorageModeShared;
                id<MTLTexture> texture = i ? [device newTextureWithDescriptor:td]
                    : [output newTextureWithDescriptor:td offset:0 bytesPerRow:512];
                if (!texture) return 5;
                pass.colorAttachments[i].texture = texture;
                pass.colorAttachments[i].loadAction = MTLLoadActionClear;
                pass.colorAttachments[i].clearColor = MTLClearColorMake(0, 0, 0, 0);
                pass.colorAttachments[i].storeAction = i ? MTLStoreActionDontCare : MTLStoreActionStore;
            }
            [passes addObject:pass];
        }
        if (outputs[0].gpuAddress == outputs[1].gpuAddress) return 6;
        for (NSUInteger owner = 0; owner < 2; owner++) {
            NSUInteger count = owner || both ? pressure : 1;
            id<MTLBuffer> output = outputs[owner];
            fprintf(console, "NEO_GROWTH_TARGET dva=0x%llx bytes=%lu owner=%lu triangles=%lu\n",
                output.gpuAddress, bytes, owner, count);
            id<MTLCommandBuffer> command = [queues[owner] commandBuffer];
            id<MTLRenderCommandEncoder> encoder =
                [command renderCommandEncoderWithDescriptor:passes[owner]];
            if (!encoder) return 7;
            [encoder setRenderPipelineState:pipeline];
            [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:count * 3];
            [encoder endEncoding];
            fprintf(console, "NEO_GROWTH_FIRST_COMMIT owner=%lu\n", owner);
            fprintf(console, "G17P_PARTIAL_ARM_CAPTURE\n");
            [command commit];
            [command waitUntilCompleted];
            BOOL exact = command.status == MTLCommandBufferStatusCompleted;
            for (NSUInteger old = 0; old <= owner; old++) {
                const uint32_t *actual = outputs[old].contents;
                uint32_t expected = (uint32_t)(28 * (old || both ? pressure : 1));
                for (NSUInteger i = 0; i < bytes / 4; i++)
                    exact &= actual[i] == (i ? 0 : expected);
            }
            fprintf(console, "NEO_GROWTH_DONE owner=%lu exact=%d status=%ld\n",
                owner, exact, (long)command.status);
            // All queues, passes and output buffers remain strongly retained.
            fprintf(console, "G17P_PARTIAL_ARM_CAPTURE\n");
            if (!exact) return 8;
        }
        return queues.count == 2 && outputs.count == 2 && passes.count == 2 ? 0 : 9;
    }
}
