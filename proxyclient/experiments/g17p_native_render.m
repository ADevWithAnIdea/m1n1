// SPDX-License-Identifier: MIT
// Minimal own-source render workload used to capture one matched G17P pass.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static NSString *const metallib_path =
    @"/System/Volumes/Data/Users/Shared/g17prender.metallib";

enum { default_triangle_count = 16384 };

static FILE *open_console(void)
{
    FILE *console = fopen("/dev/console", "w");
    if (console != NULL)
        setvbuf(console, NULL, _IONBF, 0);
    return console;
}

int main(int argc, const char **argv)
{
    @autoreleasepool {
        unsigned long triangle_count = default_triangle_count;
        if (argc == 2) {
            char *end = NULL;
            triangle_count = strtoul(argv[1], &end, 0);
            if (end == argv[1] || *end != '\0' || triangle_count == 0 ||
                triangle_count > UINT32_MAX / 3) {
                fprintf(stderr, "G17P_RENDER_ERROR triangle-count\n");
                return 1;
            }
        }
        const NSUInteger vertex_count = triangle_count * 3;
        const NSUInteger width = 128;
        const NSUInteger height = 37;
        const NSUInteger bytes_per_row = 512;
        const NSUInteger output_size = bytes_per_row * height;
        NSError *error = nil;
        FILE *console = open_console();
        if (console != NULL)
            fprintf(console, "G17P_RENDER_START pid=%d\n", getpid());
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            fprintf(stderr, "G17P_RENDER_ERROR no-device\n");
            return 1;
        }

        NSURL *library_url = [NSURL fileURLWithPath:metallib_path];
        id<MTLLibrary> library = [device newLibraryWithURL:library_url error:&error];
        if (library == nil) {
            fprintf(stderr, "G17P_RENDER_ERROR library %s\n",
                    [[error localizedDescription] UTF8String]);
            return 2;
        }

        MTLRenderPipelineDescriptor *pipeline_desc =
            [[MTLRenderPipelineDescriptor alloc] init];
        pipeline_desc.vertexFunction = [library newFunctionWithName:@"vertex_main"];
        pipeline_desc.fragmentFunction = [library newFunctionWithName:@"fragment_main"];
        pipeline_desc.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        id<MTLRenderPipelineState> pipeline =
            [device newRenderPipelineStateWithDescriptor:pipeline_desc error:&error];
        if (pipeline == nil) {
            fprintf(stderr, "G17P_RENDER_ERROR pipeline %s\n",
                    [[error localizedDescription] UTF8String]);
            return 3;
        }

        id<MTLBuffer> output =
            [device newBufferWithLength:output_size
                                options:MTLResourceStorageModeShared];
        memset([output contents], 0, output_size);
        MTLTextureDescriptor *texture_desc =
            [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                             width:width
                                            height:height
                                         mipmapped:NO];
        texture_desc.usage = MTLTextureUsageRenderTarget;
        texture_desc.storageMode = MTLStorageModeShared;
        id<MTLTexture> target =
            [output newTextureWithDescriptor:texture_desc
                                      offset:0
                                 bytesPerRow:bytes_per_row];
        if (target == nil) {
            fprintf(stderr, "G17P_RENDER_ERROR texture\n");
            return 4;
        }

        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        pass.colorAttachments[0].texture = target;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 1);

        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        id<MTLRenderCommandEncoder> encoder =
            [command renderCommandEncoderWithDescriptor:pass];
        [encoder setRenderPipelineState:pipeline];
        MTLViewport viewport = {0, 0, width, height, 0, 1};
        [encoder setViewport:viewport];
        [encoder drawPrimitives:MTLPrimitiveTypeTriangle
                    vertexStart:0
                    vertexCount:vertex_count];
        [encoder endEncoding];

        printf("G17P_RENDER_READY pid=%d output=0x%llx size=0x%lx "
               "triangles=%d vertices=%d\n",
               getpid(), (unsigned long long)[output gpuAddress],
               (unsigned long)output_size, (int)triangle_count,
               (int)vertex_count);
        fflush(stdout);
        if (console != NULL)
            fprintf(console,
                    "G17P_RENDER_READY pid=%d output=0x%llx size=0x%lx "
                    "triangles=%d vertices=%d\n",
                    getpid(), (unsigned long long)[output gpuAddress],
                    (unsigned long)output_size, (int)triangle_count,
                    (int)vertex_count);
        sleep(1);

        [command commit];
        [command waitUntilCompleted];
        const uint8_t *bytes = [output contents];
        size_t exact = 0;
        for (size_t offset = 0; offset < output_size; offset += 4) {
            if (bytes[offset + 0] == 0xbf && bytes[offset + 1] == 0x80 &&
                bytes[offset + 2] == 0x40 && bytes[offset + 3] == 0xff)
                exact++;
        }
        printf("G17P_RENDER_DONE status=%ld error=%s exact_pixels=%zu/%lu "
               "first=%02x%02x%02x%02x\n",
               (long)[command status],
               [command error] ? [[[command error] localizedDescription] UTF8String]
                               : "none",
               exact, (unsigned long)(width * height), bytes[0], bytes[1],
               bytes[2], bytes[3]);
        fflush(stdout);
        if (console != NULL)
            fprintf(console,
                    "G17P_RENDER_DONE status=%ld exact_pixels=%zu/%lu "
                    "first=%02x%02x%02x%02x\n",
                    (long)[command status], exact,
                    (unsigned long)(width * height), bytes[0], bytes[1],
                    bytes[2], bytes[3]);
        return exact == width * height ? 0 : 5;
    }
}
