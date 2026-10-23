// SPDX-License-Identifier: MIT
// Two independent clients use mutable 4096-word thread-private storage.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#include "g16c_private_hash4096_oracle.h"

typedef struct { uint64_t gpu; uint32_t selector; int32_t pid; } Ready;
typedef struct { uint32_t words[32]; double start, end; } Result;

static int transfer(int fd, void *buffer, size_t bytes, int writing) {
    unsigned char *p = buffer;
    while (bytes) {
        ssize_t n = writing ? write(fd, p, bytes) : read(fd, p, bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        p += n; bytes -= (size_t)n;
    }
    return 1;
}
static uint32_t expected(unsigned tid, uint32_t selector) { return g16c_private_hash(tid, selector); }
static int verify(const Result *r, uint32_t selector) {
    if (!(r->start > 0 && r->end > r->start)) return 0;
    for (unsigned i = 0; i < 32; ++i)
        if (r->words[i] != (i < 16 ? expected(i, selector) : 0xa5a5a5a5u)) return 0;
    return 1;
}

@interface Work : NSObject
@property(strong) id<MTLDevice> device;
@property(strong) id<MTLBuffer> output;
@property(strong) id<MTLCommandQueue> queue;
@property(strong) id<MTLCommandBuffer> command;
@end
@implementation Work
@end

static Work *prepare(uint32_t selector) {
    Work *w = [Work new];
    w.device = MTLCreateSystemDefaultDevice();
    if (!w.device) return nil;
    NSError *error = nil;
  NSString *source=@"#include <metal_stdlib>\nusing namespace metal;\n"
   "uint rotl(uint v,uint s){return (v<<s)|(v>>(32u-s));}\n"
   "kernel void hash_private(device uint *output [[buffer(0)]],"
   "constant uint &selector [[buffer(1)]],uint i [[thread_position_in_grid]]){"
   "uint private_words[4096];uint value=0x5a110000u^i^selector;"
   "for(uint j=0u;j<4096u;j++){value=rotl(value,7u)+0x9e3779b9u+j;"
   "private_words[j]=value^((j+1u)*0x045d9f3bu);}"
   "for(uint step=0u;step<4096u;step++){uint index=(step*13u+selector+i)&4095u;"
   "uint partner=(index+17u)&4095u;private_words[index]="
   "rotl(private_words[index]^private_words[partner],5u)+step+selector;}"
   "uint hash=0x31415926u^i;for(uint j=0u;j<4096u;j++)"
   "hash=rotl(hash,3u)^private_words[(j*29u+selector)&4095u];output[i]=hash;}\n";
    id<MTLLibrary> library = [w.device newLibraryWithSource:source options:nil error:&error];
    id<MTLComputePipelineState> pipeline = library ? [w.device newComputePipelineStateWithFunction:
        [library newFunctionWithName:@"hash_private"] error:&error] : nil;
    w.output = [w.device newBufferWithLength:128 options:MTLResourceStorageModeShared];
    w.queue = [w.device newCommandQueue];
    w.command = [w.queue commandBuffer];
    if (!pipeline || !w.output || !w.queue || !w.command) { NSLog(@"prepare: %@", error); return nil; }
    memset(w.output.contents, 0xa5, 128);
    id<MTLComputeCommandEncoder> encoder = [w.command computeCommandEncoder];
    if (!encoder) return nil;
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:w.output offset:0 atIndex:0];
    [encoder setBytes:&selector length:sizeof(selector) atIndex:1];
    [encoder dispatchThreads:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(16,1,1)];
    [encoder endEncoding];
    return w;
}
static int finish(Work *w, Result *r) {
    [w.command waitUntilCompleted];
    if (w.command.status != MTLCommandBufferStatusCompleted) {
        NSLog(@"command: %@", w.command.error); return 0;
    }
    memcpy(r->words, w.output.contents, sizeof(r->words));
    r->start = w.command.GPUStartTime; r->end = w.command.GPUEndTime;
    return 1;
}
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 5 && !strcmp(argv[1], "--child")) {
            int ready = atoi(argv[2]), go = atoi(argv[3]), done = atoi(argv[4]);
            Work *w = prepare(10); if (!w) return 2;
            Ready identity = {w.output.gpuAddress, 10, getpid()};
            char token; Result r;
            if (!transfer(ready, &identity, sizeof(identity), 1) ||
                !transfer(go, &token, 1, 0) || token != 'C') return 3;
            [w.command commit];
            if (!finish(w, &r) || !verify(&r, 10) || !transfer(done, &r, sizeof(r), 1)) return 4;
            // Keep this client's resources alive until the parent releases both.
            if (!transfer(go, &token, 1, 0) || token != 'R') return 5;
            close(ready); close(go); close(done); return 0;
        }
        if (argc != 1) return 1;
        int ready[2], go[2], done[2];
        if (pipe(ready) || pipe(go) || pipe(done)) return 6;
        char a[16], b[16], c[16];
        snprintf(a, sizeof(a), "%d", ready[1]); snprintf(b, sizeof(b), "%d", go[0]);
        snprintf(c, sizeof(c), "%d", done[1]);
        char *child_args[] = {argv[0], "--child", a, b, c, NULL};
        posix_spawn_file_actions_t actions;
        if (posix_spawn_file_actions_init(&actions)) return 7;
        posix_spawn_file_actions_addclose(&actions, ready[0]);
        posix_spawn_file_actions_addclose(&actions, go[1]);
        posix_spawn_file_actions_addclose(&actions, done[0]);
        pid_t child;
        int spawn = posix_spawn(&child, argv[0], &actions, NULL, child_args, environ);
        posix_spawn_file_actions_destroy(&actions);
        if (spawn) return 7;
        close(ready[1]); close(go[0]); close(done[1]);
        Ready second;
        if (!transfer(ready[0], &second, sizeof(second), 0) || second.pid != child || second.selector != 10) return 8;
        Work *first = prepare(9); if (!first) return 2;
        printf("READY before commit; clients=2; gpu_output0=0x%llx; gpu_output1=0x%llx; size=128; pids=%d,%d\n",
            (unsigned long long)first.output.gpuAddress, (unsigned long long)second.gpu, getpid(), child);
        fflush(stdout); if (getchar() == EOF) return 9;
        [first.command commit];
        // Allow macOS to publish the first held kick before the other process.
        usleep(100000);
        char token = 'C';
        if (!transfer(go[1], &token, 1, 1)) return 3;
        Result results[2];
        if (!finish(first, &results[0]) || !transfer(done[0], &results[1], sizeof(results[1]), 0)) return 4;
        for (unsigned job = 0; job < 2; ++job) {
            if (!verify(&results[job], job ? 10 : 9)) return 10;
            printf("METAL_GPU_INTERVAL %u start=%.9f end=%.9f\n", job, results[job].start, results[job].end);
            printf("CLIENT_OUTPUT %u:", job);
            for (unsigned i = 0; i < 16; ++i) printf(" %08x", results[job].words[i]);
            putchar('\n');
        }
        puts("PASS: two independent Metal clients, all 32 output words and 128 guard bytes");
        puts("REPLAY READY: holding Metal resources; press Enter to release");
        fflush(stdout); if (getchar() == EOF) return 9;
        token = 'R'; if (!transfer(go[1], &token, 1, 1)) return 3;
        close(ready[0]); close(go[1]); close(done[0]);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 11;
    }
    return 0;
}
