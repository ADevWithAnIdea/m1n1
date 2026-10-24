// SPDX-License-Identifier: MIT
// Match the Linux regression's order: a separate render client exits before
// the two-queue compute client warms, admits a late process and resumes.
#define main compute_late_main
#include "metal_g16c_compute_late_client.m"
#undef main

static int render_bootstrap(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return 20;
        NSError *error = nil;
        NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
            "vertex float4 triangle(uint id [[vertex_id]]) {"
            "float2 p[3]={float2(-1,-1),float2(3,-1),float2(-1,3)};"
            "return float4(p[id],0,1);}\n"
            "fragment float4 red() {return float4(1,0,0,1);}\n";
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        MTLRenderPipelineDescriptor *pipelineDescriptor = [MTLRenderPipelineDescriptor new];
        pipelineDescriptor.vertexFunction = [library newFunctionWithName:@"triangle"];
        pipelineDescriptor.fragmentFunction = [library newFunctionWithName:@"red"];
        pipelineDescriptor.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA8Unorm;
        id<MTLRenderPipelineState> pipeline = [device
            newRenderPipelineStateWithDescriptor:pipelineDescriptor error:&error];
        id<MTLBuffer> output = [device newBufferWithLength:256 options:MTLResourceStorageModeShared];
        MTLTextureDescriptor *descriptor = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:1 height:1 mipmapped:NO];
        descriptor.storageMode = MTLStorageModeShared;
        descriptor.usage = MTLTextureUsageRenderTarget;
        id<MTLTexture> texture = [output newTextureWithDescriptor:descriptor offset:0 bytesPerRow:256];
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        if (!library || !pipeline || !output || !texture || !queue || !command) {
            NSLog(@"render bootstrap: %@", error); return 21;
        }
        memset(output.contents, 0xa5, 256);
        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor new];
        pass.colorAttachments[0].texture = texture;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0,0,1,1);
        id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:pass];
        if (!encoder) return 22;
        [encoder setRenderPipelineState:pipeline];
        [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        [encoder endEncoding];
        printf("READY_RENDER before commit; gpu_output=0x%llx; size=256; pid=%d\n",
            (unsigned long long)output.gpuAddress, getpid());
        fflush(stdout); if (getchar() == EOF) return 23;
        [command commit]; [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted ||
            !(command.GPUStartTime > 0 && command.GPUEndTime > command.GPUStartTime)) {
            NSLog(@"render bootstrap command: %@", command.error); return 24;
        }
        const uint8_t *actual = output.contents;
        for (unsigned i=0; i<256; i++) {
            uint8_t want = i>=4 ? 0xa5 : (i==0 || i==3 ? 255 : 0);
            if (actual[i] != want) return 25;
        }
        printf("RENDER_GPU_INTERVAL start=%.9f end=%.9f\n", command.GPUStartTime, command.GPUEndTime);
        puts("RENDER_OUTPUT_PASS: red pixel and all252 guard bytes; renderer process exiting");
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1], "--render-bootstrap")) return render_bootstrap();
    if (argc==1) {
        // Parent opens no Metal device until this entire process has exited.
        char *render_args[] = {argv[0], "--render-bootstrap", NULL};
        pid_t child;
        if (posix_spawn(&child, argv[0], NULL, NULL, render_args, environ)) return 26;
        int status;
        if (waitpid(child, &status, 0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)) return 27;
        puts("RENDER_PROCESS_EXITED status=0 before compute Metal device creation");
        fflush(stdout);
    }
    return compute_late_main(argc, argv);
}
