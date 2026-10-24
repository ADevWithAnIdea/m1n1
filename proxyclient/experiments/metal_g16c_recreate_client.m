// SPDX-License-Identifier: MIT
// Two strictly sequential fresh Metal processes, with no device in the parent.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(unsigned epoch)
{
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return 2;
        NSError *error = nil;
        NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
            "kernel void fill(device uint *out [[buffer(0)]],"
            "constant uint &base [[buffer(1)]], uint tid [[thread_position_in_grid]])"
            "{ out[tid] = base + tid; }";
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        if (!library) { NSLog(@"Metal compile: %@", error); return 3; }
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:
            [library newFunctionWithName:@"fill"] error:&error];
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLBuffer> output = [device newBufferWithLength:128 options:MTLResourceStorageModeShared];
        if (!pipeline || !queue || !output) return 3;
        memset(output.contents, 0xa5, 128);
        id<MTLCommandBuffer> command = [queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (!command || !encoder) return 3;
        unsigned base = 0x5a330000u + epoch * 0x100u;
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:output offset:0 atIndex:0];
        [encoder setBytes:&base length:sizeof(base) atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(16, 1, 1) threadsPerThreadgroup:MTLSizeMake(16, 1, 1)];
        [encoder endEncoding];
        printf("READY_CHILD %u gpu_output=0x%llx size=128\n", epoch,
            (unsigned long long)output.gpuAddress);
        fflush(stdout);
        if (getchar() == EOF) return 7;
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            NSLog(@"Metal command: %@", command.error); return 4;
        }
        const unsigned *words = output.contents;
        for (unsigned i = 0; i < 16; ++i) if (words[i] != base + i) return 5;
        const unsigned char *bytes = output.contents;
        for (unsigned i = 64; i < 128; ++i) if (bytes[i] != 0xa5) return 5;
        if (!(command.GPUStartTime > 0 && command.GPUEndTime > command.GPUStartTime)) return 6;
        printf("PASS_CHILD %u words=16 guards=64 start=%.9f end=%.9f\n", epoch,
            command.GPUStartTime, command.GPUEndTime);
        printf("CHILD_OUTPUT %u ", epoch);
        for (unsigned i = 0; i < 128; ++i) printf("%02x", bytes[i]);
        puts("");
        printf("HOLD_CHILD %u press Enter to exit\n", epoch);
        fflush(stdout);
        if (getchar() == EOF) return 7;
    }
    return 0;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    if (argc == 3 && !strcmp(argv[1], "--child")) {
        unsigned epoch = (unsigned)strtoul(argv[2], NULL, 10);
        if (epoch > 1) return 8;
        return child(epoch);
    }
    if (argc != 1) return 8;
    for (unsigned epoch = 0; epoch < 2; ++epoch) {
        pid_t pid = fork();
        if (pid < 0) return 9;
        if (pid == 0) {
            execl(argv[0], argv[0], "--child", epoch ? "1" : "0", (char *)NULL);
            _exit(9);
        }
        int status;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 10;
        printf("CHILD_EXITED %u all_Metal_objects_released=1\n", epoch);
        // Permit the native driver's asynchronous close work before reopening.
        if (usleep(100000)) return 11;
    }
    puts("PASS_RECREATE_CLIENT children=2 words=32 guards=128");
    return 0;
}
