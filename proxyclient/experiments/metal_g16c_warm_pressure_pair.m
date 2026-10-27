// SPDX-License-Identifier: MIT
// Own Metal workload: two retained processes, warmed PBs, then paired work.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;

static id<MTLCommandBuffer> encode(id<MTLCommandQueue> queue,
    id<MTLComputePipelineState> compute, id<MTLRenderPipelineState> pipeline,
    id<MTLBuffer> arguments, id<MTLBuffer> output, id<MTLTexture> texture) {
    uint32_t instances=200000;
    id<MTLCommandBuffer> command=[queue commandBuffer];
    id<MTLComputeCommandEncoder> generate=[command computeCommandEncoder];
    if(!command || !generate) return nil;
    [generate setComputePipelineState:compute];
    [generate setBuffer:arguments offset:0 atIndex:0];
    [generate setBytes:&instances length:sizeof(instances) atIndex:1];
    [generate dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
    [generate endEncoding];
    MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];
    pass.colorAttachments[0].texture=texture;
    pass.colorAttachments[0].loadAction=MTLLoadActionClear;
    pass.colorAttachments[0].clearColor=MTLClearColorMake(0,0,0,0);
    pass.colorAttachments[0].storeAction=MTLStoreActionStore;
    pass.visibilityResultBuffer=output;
    id<MTLRenderCommandEncoder> render=[command renderCommandEncoderWithDescriptor:pass];
    if(!render) return nil;
    [render setRenderPipelineState:pipeline];
    [render setVisibilityResultMode:MTLVisibilityResultModeCounting offset:256];
    [render drawPrimitives:MTLPrimitiveTypeTriangle indirectBuffer:arguments indirectBufferOffset:0];
    [render endEncoding];
    return command;
}

static void seed_output(id<MTLBuffer> output,int child) {
    memset(output.contents,child?0x5a:0xa5,512);
    memset((uint8_t *)output.contents+256,0,8);
}
static int verify(id<MTLCommandBuffer> command,id<MTLBuffer> output,int child) {
    if(command.status!=MTLCommandBufferStatusCompleted) {
        NSLog(@"Command failed: %@",command.error);return 4;
    }
    const uint8_t red[4]={255,0,0,255},green[4]={0,255,0,255};
    const uint8_t *bytes=output.contents;uint64_t count;
    memcpy(&count,bytes+256,8);
    if(memcmp(bytes,child?green:red,4) || count!=200000) {
        fprintf(stderr,"PAIR output mismatch tag=%c count=%llu\n",child?'B':'A',(unsigned long long)count);
        return 5;
    }
    for(unsigned i=4;i<512;i++) if(!(i>=256&&i<264) && bytes[i]!=(child?0x5a:0xa5)) {
        fprintf(stderr,"PAIR guard mismatch tag=%c byte=%u\n",child?'B':'A',i);return 6;
    }
    return 0;
}
static int token(int fd,char expected,int writing) {
    char value=expected;
    return writing ? write(fd,&value,1)==1 : read(fd,&value,1)==1&&value==expected;
}
static int phase(int child,int notify,int proceed) {
    char model[64]={0};size_t size=sizeof(model);
    if(sysctlbyname("hw.model",model,&size,NULL,0) || strcmp(model,"Mac16,5")) return 2;
    @autoreleasepool {
        id<MTLDevice> device=MTLCreateSystemDefaultDevice();
        if(!device)return 2;
        NSString *source=@"#include <metal_stdlib>\nusing namespace metal;\n"
            "kernel void arguments(device uint *args [[buffer(0)]], constant uint &count [[buffer(1)]]) {"
            "args[0]=3u; args[1]=count; args[2]=0u; args[3]=0u; }\n"
            "vertex float4 triangle(uint id [[vertex_id]]) {"
            "const float2 p[3]={float2(-1,-1),float2(3,-1),float2(-1,3)};"
            "return float4(p[id],0,1); }\n"
            "fragment float4 red() { return float4(1,0,0,1); }\n"
            "fragment float4 green() { return float4(0,1,0,1); }\n";
        NSError *error=nil;
        id<MTLLibrary> library=[device newLibraryWithSource:source options:nil error:&error];
        if(!library){NSLog(@"Metal compile: %@",error);return 3;}
        MTLRenderPipelineDescriptor *descriptor=[MTLRenderPipelineDescriptor new];
        descriptor.vertexFunction=[library newFunctionWithName:@"triangle"];
        descriptor.fragmentFunction=[library newFunctionWithName:child?@"green":@"red"];
        descriptor.inputPrimitiveTopology=MTLPrimitiveTopologyClassTriangle;
        descriptor.colorAttachments[0].pixelFormat=MTLPixelFormatRGBA8Unorm;
        id<MTLRenderPipelineState> pipeline=[device newRenderPipelineStateWithDescriptor:descriptor error:&error];
        id<MTLComputePipelineState> compute=[device newComputePipelineStateWithFunction:[library newFunctionWithName:@"arguments"] error:&error];
        id<MTLBuffer> output=[device newBufferWithLength:512 options:MTLResourceStorageModeShared];
        id<MTLBuffer> arguments=[device newBufferWithLength:16 options:MTLResourceStorageModePrivate];
        id<MTLCommandQueue> queue=[device newCommandQueue];
        MTLTextureDescriptor *td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:1 height:1 mipmapped:NO];
        td.storageMode=MTLStorageModeShared;td.usage=MTLTextureUsageRenderTarget;
        id<MTLTexture> texture=[output newTextureWithDescriptor:td offset:0 bytesPerRow:256];
        if(!pipeline||!compute||!output||!arguments||!queue||!texture)return 3;
        seed_output(output,child);
        id<MTLCommandBuffer> warm=encode(queue,compute,pipeline,arguments,output,texture);
        if(!warm)return 3;
        [warm commit];[warm waitUntilCompleted];
        int rc=verify(warm,output,child);if(rc)return rc;
        printf("PAIR_WARM_PASS tag=%c instances=200000 guards=500\n",child?'B':'A');fflush(stdout);
        seed_output(output,child);
        id<MTLCommandBuffer> command=encode(queue,compute,pipeline,arguments,output,texture);
        if(!command)return 3;
        printf("PAIR_CLIENT_READY tag=%c gpu_output=0x%llx cpu_output=%p size=512 gpu_arguments=0x%llx instances=200000\n",
            child?'B':'A',(unsigned long long)output.gpuAddress,output.contents,(unsigned long long)arguments.gpuAddress);
        fflush(stdout);
        if(child) {if(!token(notify,'R',1)||!token(proceed,'G',0))return 7;}
        else {
            if(!token(notify,'R',0))return 7;
            puts("PAIR_READY before paired commit; both clients warmed and seeded");fflush(stdout);
            if(getchar()=='\n' && token(proceed,'G',1)) {} else return 7;
        }
        [command commit];[command waitUntilCompleted];
        rc=verify(command,output,child);if(rc)return rc;
        printf("PAIR_CLIENT_PASS tag=%c instances=200000 guards=500\n",child?'B':'A');fflush(stdout);
        if(child) {if(!token(notify,'D',1)||!token(proceed,'X',0))return 7;}
        else {
            if(!token(notify,'D',0))return 7;
            puts("PAIR_REPLAY_READY both outputs verified; press Enter to release");fflush(stdout);
            if(getchar()!='\n'||!token(proceed,'X',1))return 7;
        }
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc==4&&!strcmp(argv[1],"--child"))return phase(1,atoi(argv[2]),atoi(argv[3]));
    if(argc!=1)return 1;
    int ready[2],go[2];if(pipe(ready)||pipe(go))return 10;
    char notify[16],proceed[16];snprintf(notify,sizeof(notify),"%d",ready[1]);snprintf(proceed,sizeof(proceed),"%d",go[0]);
    char *child_argv[]={argv[0],"--child",notify,proceed,NULL};pid_t child;
    if(posix_spawn(&child,argv[0],NULL,NULL,child_argv,environ))return 11;
    close(ready[1]);close(go[0]);int rc=phase(0,ready[0],go[1]);
    close(ready[0]);close(go[1]);int status;
    if(rc)return rc;
    if(waitpid(child,&status,0)!=child||!WIFEXITED(status)||WEXITSTATUS(status))return 12;
    puts("PAIR_PASS both retained clients, four output checks, 2000 guards");return 0;
}
