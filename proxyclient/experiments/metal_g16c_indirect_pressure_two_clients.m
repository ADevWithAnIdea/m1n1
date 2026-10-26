// SPDX-License-Identifier: MIT
// Two retained Metal clients: a count2 draw pins pool0, then count200000
// exercises a non-bootstrap parameter pool with an independent output oracle.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;

static int phase(uint32_t instances,int notify,int proceed) {
    // This executable is compiled on the host but runs only on the target.
    char model[64] = {0};
    size_t model_size = sizeof(model);
    if (sysctlbyname("hw.model", model, &model_size, NULL, 0) || strcmp(model, "Mac16,5")) {
        fputs("This workload requires the verified Mac16,5 target\n", stderr);
        return 2;
    }
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return 2;
        NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
            "kernel void arguments(device uint *args [[buffer(0)]], constant uint &count [[buffer(1)]]) {"
            "args[0]=3u; args[1]=count; args[2]=0u; args[3]=0u; }\n"
            "vertex float4 triangle(uint id [[vertex_id]]) {"
            "const float2 p[3]={float2(-1,-1),float2(3,-1),float2(-1,3)};"
            "return float4(p[id],0,1); }\n"
            "fragment float4 red() { return float4(1,0,0,1); }\n";
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        if (!library) { NSLog(@"Metal compile: %@", error); return 3; }
        MTLRenderPipelineDescriptor *descriptor = [MTLRenderPipelineDescriptor new];
        descriptor.vertexFunction = [library newFunctionWithName:@"triangle"];
        descriptor.fragmentFunction = [library newFunctionWithName:@"red"];
        descriptor.inputPrimitiveTopology = MTLPrimitiveTopologyClassTriangle;
        descriptor.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA8Unorm;
        id<MTLRenderPipelineState> renderPipeline = [device newRenderPipelineStateWithDescriptor:descriptor error:&error];
        id<MTLComputePipelineState> argumentPipeline = [device newComputePipelineStateWithFunction:
            [library newFunctionWithName:@"arguments"] error:&error];
        id<MTLBuffer> output = [device newBufferWithLength:512 options:MTLResourceStorageModeShared];
        // Private indirect storage keeps draw geometry unavailable to CPU-side
        // submission sizing. Grow the instance count only after a count1 gate.
        id<MTLBuffer> arguments = [device newBufferWithLength:16 options:MTLResourceStorageModePrivate];
        id<MTLCommandQueue> queue = [device newCommandQueue];
        MTLTextureDescriptor *textureDescriptor = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:1 height:1 mipmapped:NO];
        textureDescriptor.storageMode = MTLStorageModeShared;
        textureDescriptor.usage = MTLTextureUsageRenderTarget;
        id<MTLTexture> texture = [output newTextureWithDescriptor:textureDescriptor offset:0 bytesPerRow:256];
        if (!renderPipeline || !argumentPipeline || !output || !arguments || !queue || !texture) {
            NSLog(@"Metal resources: %@", error); return 3;
        }
        memset(output.contents, 0xa5, 512);
        memset((uint8_t *)output.contents + 256, 0, 8);
        id<MTLCommandBuffer> command = [queue commandBuffer];
        id<MTLComputeCommandEncoder> generate = [command computeCommandEncoder];
        if (!command || !generate) return 3;
        [generate setComputePipelineState:argumentPipeline];
        [generate setBuffer:arguments offset:0 atIndex:0];
        [generate setBytes:&instances length:sizeof(instances) atIndex:1];
        [generate dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
        [generate endEncoding];
        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        pass.colorAttachments[0].texture = texture;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0,0,0,0);
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        pass.visibilityResultBuffer = output;
        id<MTLRenderCommandEncoder> render = [command renderCommandEncoderWithDescriptor:pass];
        if (!render) return 3;
        [render setRenderPipelineState:renderPipeline];
        [render setVisibilityResultMode:MTLVisibilityResultModeCounting offset:256];
        [render drawPrimitives:MTLPrimitiveTypeTriangle indirectBuffer:arguments indirectBufferOffset:0];
        [render endEncoding];
        printf("READY before commit; gpu_output=0x%llx; cpu_output=%p; size=512; width=1; height=1; row_bytes=256; samples=1; instances=%u; gpu_arguments=0x%llx; argument_bytes=16\n",
            (unsigned long long)output.gpuAddress, output.contents, instances,
            (unsigned long long)arguments.gpuAddress);
        fflush(stdout); getchar();
        [command commit]; [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) { NSLog(@"Metal command: %@", command.error); return 4; }
        const uint8_t red[4] = {255,0,0,255};
        const uint8_t *bytes = output.contents;
        uint64_t visibility;
        memcpy(&visibility, bytes+256, sizeof(visibility));
        if (memcmp(bytes, red, 4) || visibility != instances) {
            fprintf(stderr, "Indirect output failed: count=%llu expected=%u\n", (unsigned long long)visibility, instances);
            return 5;
        }
        for (unsigned i=4; i<512; i++)
            if (!(i>=256 && i<264) && bytes[i]!=0xa5) {
                fprintf(stderr, "Indirect output guard changed at %u\n", i); return 6;
            }
        printf("PASS: Metal indirect draw rendered red, counted %u primitives and preserved all 500 guard bytes\n", instances);
        if(notify>=0) {
            char token='R';
            if(write(notify,&token,1)!=1 || read(proceed,&token,1)!=1 || token!='G')return 7;
        } else {
            puts("REPLAY READY: holding Metal resources; press Enter to release");
            fflush(stdout);getchar();
        }
    }
    return 0;
}

int main(int argc,char **argv) {
    if(argc==4 && !strcmp(argv[1],"--child"))
        return phase(2,atoi(argv[2]),atoi(argv[3]));
    if(argc!=1)return 1;
    int ready[2],go[2];if(pipe(ready)||pipe(go))return 10;
    char notify[16],proceed[16];
    snprintf(notify,sizeof(notify),"%d",ready[1]);snprintf(proceed,sizeof(proceed),"%d",go[0]);
    char *child_argv[]={argv[0],"--child",notify,proceed,NULL};pid_t child;
    if(posix_spawn(&child,argv[0],NULL,NULL,child_argv,environ))return 11;
    close(ready[1]);close(go[0]);char token;
    if(read(ready[0],&token,1)!=1 || token!='R')return 12;
    puts("CHILD RETAINED: count2 output verified; preparing parent pressure200000");fflush(stdout);
    int rc=phase(200000,-1,-1);if(rc)return rc;
    token='G';if(write(go[1],&token,1)!=1)return 13;
    close(ready[0]);close(go[1]);int status;
    if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return 14;
    puts("PASS: independent retained-child and non-bootstrap pressure Metal clients");return 0;
}
