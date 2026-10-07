// SPDX-License-Identifier: MIT
// Native growth witness: no warm-up, blit, compute or presentation.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 4 || argc > 5) return 1;
        char *end;
        NSUInteger count = strtoul(argv[2], &end, 10);
        if (!*argv[2] || *end || !count || count > 75000000) return 1;
        BOOL memoryless = !strcmp(argv[3], "memoryless");
        if (!memoryless && strcmp(argv[3], "stored")) return 1;
        BOOL allowLimit = argc == 5 && !strcmp(argv[4], "allow-limit");
        if (argc == 5 && !allowLimit) return 1;
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
        id<MTLBuffer> target = [device newBufferWithLength:bytes
            options:MTLResourceStorageModeShared];
        if (!target) return 4;
        memset(target.contents, 0xa5, bytes);
        fprintf(console, "NEO_GROWTH_CONFIG triangles=%lu mode=%s expected=%lu\n",
            count, argv[3], count * 28);
        fprintf(console, "NEO_GROWTH_TARGET dva=0x%llx bytes=%lu\n", target.gpuAddress, bytes);
        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        for (NSUInteger i = 0; i < 8; i++) {
            MTLTextureDescriptor *td = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatR32Uint
                width:128 height:128 mipmapped:NO];
            td.usage = MTLTextureUsageRenderTarget;
            td.storageMode = i ? (memoryless ? MTLStorageModeMemoryless : MTLStorageModePrivate)
                               : MTLStorageModeShared;
            id<MTLTexture> texture = i ? [device newTextureWithDescriptor:td]
                : [target newTextureWithDescriptor:td offset:0 bytesPerRow:512];
            if (!texture) return 5;
            pass.colorAttachments[i].texture = texture;
            pass.colorAttachments[i].loadAction = MTLLoadActionClear;
            pass.colorAttachments[i].clearColor = MTLClearColorMake(0, 0, 0, 0);
            pass.colorAttachments[i].storeAction = i && memoryless
                ? MTLStoreActionDontCare : MTLStoreActionStore;
        }
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:pass];
        if (!encoder) return 6;
        [encoder setRenderPipelineState:pipeline];
        [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:count * 3];
        [encoder endEncoding];
        fprintf(console, "NEO_GROWTH_FIRST_COMMIT\n");
        // Synchronous marker supplies a coherent host boundary before the kick.
        fprintf(console, "G17P_PARTIAL_ARM_CAPTURE\n");
        [command commit];
        [command waitUntilCompleted];
        const uint32_t *actual = target.contents;
        NSUInteger mismatches = 0;
        for (NSUInteger i = 0; i < bytes / 4; i++)
            mismatches += actual[i] != (i ? 0 : count * 28);
        BOOL exact = command.status == MTLCommandBufferStatusCompleted && !mismatches;
        fprintf(console, "NEO_GROWTH_RESULT status=%ld actual=%u mismatches=%lu "
            "error_domain=%s error_code=%ld\n", (long)command.status, actual[0],
            mismatches, command.error ? command.error.domain.UTF8String : "none",
            command.error ? (long)command.error.code : 0L);
        fprintf(console, "NEO_GROWTH_DONE exact=%d\n", exact);
        BOOL limit = (allowLimit && command.status == MTLCommandBufferStatusError &&
            [command.error.domain isEqualToString:MTLCommandBufferErrorDomain] &&
            (command.error.code == MTLCommandBufferErrorOutOfMemory ||
             command.error.code == MTLCommandBufferErrorMemoryless));
        if (limit)
            fprintf(console, "NEO_GROWTH_LIMIT status=%ld code=%ld\n",
                (long)command.status, (long)command.error.code);
        // Retain the target for a stopped read. This is not a GPU settle delay.
        fprintf(console, "G17P_PARTIAL_ARM_CAPTURE\n");
        if (target.length != bytes || queue.device != device) return 7;
        return exact || limit ? 0 : 8;
    }
}
