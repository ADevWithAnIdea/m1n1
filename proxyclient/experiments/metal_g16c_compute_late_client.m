// SPDX-License-Identifier: MIT
// Three bounded phases: warm both queues, create a late client, resume the parent.
// Capture/replay each phase with full UAT state; all Metal resources stay owned.
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

typedef struct { uint64_t gpu; uint32_t iterations; int32_t pid; } Ready;
typedef struct { uint32_t words[40]; double start, end; } Result;

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
static uint32_t expected(unsigned tid, uint32_t iterations) {
    uint32_t value = 0x5a110000u ^ tid;
    for (uint32_t j = 0; j < iterations; ++j)
        value = ((value << 7) | (value >> 25)) + 0x9e3779b9u + j;
    return value;
}
static int verify(const Result *r, uint32_t iterations, unsigned commands) {
    if (!(r->start > 0 && r->end > r->start)) return 0;
    if (commands < 1 || commands > 8) return 0;
    for (unsigned i = 0; i < 40; ++i) {
        uint32_t want = i < 16 ? expected(i, iterations) :
            (i < 16 + commands ? 0x5a220000u | (i - 16) : 0xa5a5a5a5u);
        if (r->words[i] != want) return 0;
    }
    return 1;
}

@interface Work : NSObject
@property(strong) id<MTLDevice> device;
@property(strong) id<MTLBuffer> output;
@property(strong) id<MTLCommandQueue> queue;
@property(strong) id<MTLCommandBuffer> command;
@property(strong) id<MTLComputePipelineState> pipeline;
@end
@implementation Work
@end

static Work *prepareWithDevice(uint32_t iterations, id<MTLDevice> device) {
    Work *w = [Work new];
    w.device = device ?: MTLCreateSystemDefaultDevice();
    if (!w.device) return nil;
    NSError *error = nil;
    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "kernel void fill(device uint *out [[buffer(0)]],"
        "constant uint &iterations [[buffer(1)]], constant uint &job [[buffer(2)]], uint tid [[thread_position_in_grid]]) {"
        "uint value=0x5a110000u^tid; for(uint j=0;j<iterations;j++)"
        "value=((value<<7)|(value>>25))+0x9e3779b9u+j; out[tid]=value;if(tid==0)out[16+job]=0x5a220000u|job;}";
    id<MTLLibrary> library = [w.device newLibraryWithSource:source options:nil error:&error];
    id<MTLComputePipelineState> pipeline = library ? [w.device newComputePipelineStateWithFunction:
        [library newFunctionWithName:@"fill"] error:&error] : nil;
    w.pipeline = pipeline;
    w.output = [w.device newBufferWithLength:160 options:MTLResourceStorageModeShared];
    w.queue = [w.device newCommandQueue];
    w.command = [w.queue commandBuffer];
    if (!pipeline || !w.output || !w.queue || !w.command) { NSLog(@"prepare: %@", error); return nil; }
    memset(w.output.contents, 0xa5, 160);
    id<MTLComputeCommandEncoder> encoder = [w.command computeCommandEncoder];
    if (!encoder) return nil;
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:w.output offset:0 atIndex:0];
    [encoder setBytes:&iterations length:sizeof(iterations) atIndex:1];
    uint32_t job = 0; [encoder setBytes:&job length:sizeof(job) atIndex:2];
    [encoder dispatchThreads:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(16,1,1)];
    [encoder endEncoding];
    return w;
}
static Work *prepare(uint32_t iterations) { return prepareWithDevice(iterations, nil); }
static int rearm(Work *w, uint32_t iterations, uint32_t job) {
    memset(w.output.contents, 0xa5, 160);
    w.command = [w.queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [w.command computeCommandEncoder];
    if (!w.command || !encoder) return 0;
    [encoder setComputePipelineState:w.pipeline];
    [encoder setBuffer:w.output offset:0 atIndex:0];
    [encoder setBytes:&iterations length:sizeof(iterations) atIndex:1];
    [encoder setBytes:&job length:sizeof(job) atIndex:2];
    [encoder dispatchThreads:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(16,1,1)];
    [encoder endEncoding]; return 1;
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
            // Do not open a Metal client until the parent has completed warmup.
            char token;
            if (!transfer(go, &token, 1, 0) || token != 'P') return 3;
            Work *w = prepare(1); if (!w) return 2;
            Ready identity = {w.output.gpuAddress, 1, getpid()};
            Result r;
            if (!transfer(ready, &identity, sizeof(identity), 1) ||
                !transfer(go, &token, 1, 0) || token != 'C') return 3;
            [w.command commit];
            if (!finish(w, &r) || !verify(&r, 1, 1) || !transfer(done, &r, sizeof(r), 1)) return 4;
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
        id<MTLDevice> parentDevice = MTLCreateSystemDefaultDevice();
        Work *first = prepareWithDevice(1000000, parentDevice);
        __attribute__((objc_precise_lifetime)) Work *warmSecond = prepareWithDevice(1000000, parentDevice);
        if (!first || !warmSecond) return 2;
        printf("READY_WARM before commit; gpu_output0=0x%llx; gpu_output1=0x%llx; size=160; pid=%d\n",
            (unsigned long long)first.output.gpuAddress, (unsigned long long)warmSecond.output.gpuAddress, getpid());
        fflush(stdout); if (getchar() == EOF) return 9;
        [first.command commit]; [warmSecond.command commit];
        Result warm[2];
        if (!finish(first, &warm[0]) || !finish(warmSecond, &warm[1]) ||
            !verify(&warm[0], 1000000, 1) || !verify(&warm[1], 1000000, 1)) return 10;
        for (unsigned i=0; i<2; i++)
            printf("WARM_GPU_INTERVAL %u start=%.9f end=%.9f\n", i, warm[i].start, warm[i].end);
        if (!(warm[0].start < warm[1].end && warm[1].start < warm[0].end)) return 12;
        puts("WARM_OUTPUT_PASS: all32 arithmetic words and128 guard bytes; GPU overlap verified");
        // Child initialization happens strictly after both warm GPU completions.
        char token = 'P'; if (!transfer(go[1], &token, 1, 1)) return 3;
        Ready second;
        if (!transfer(ready[0], &second, sizeof(second), 0) || second.pid != child || second.iterations != 1) return 8;
        // Keep multiple tracked writes pending on the parent's SAME output
        // and queue while the late client publishes its first work. Encode
        // every command before committing any, so poisoning is CPU-only.
        NSMutableArray<id<MTLCommandBuffer>> *backlog = [NSMutableArray new];
        for (unsigned i=0; i<8; i++) {
            if (!rearm(first, 4000000, i)) return 2;
            [backlog addObject:first.command];
        }
        printf("READY_LATE before commit; clients=2; parent_submissions=8; gpu_output0=0x%llx; gpu_output1=0x%llx; size=160; pids=%d,%d\n",
            (unsigned long long)first.output.gpuAddress, (unsigned long long)second.gpu, getpid(), child);
        fflush(stdout); if (getchar() == EOF) return 9;
        for (id<MTLCommandBuffer> command in backlog) [command commit];
        // Allow macOS to publish the held backlog before the other process.
        usleep(1000);
        token = 'C';
        if (!transfer(go[1], &token, 1, 1)) return 3;
        Result results[2];
        if (!finish(first, &results[0]) || !transfer(done[0], &results[1], sizeof(results[1]), 0)) return 4;
        for (unsigned i=0; i<backlog.count; i++) {
            id<MTLCommandBuffer> command = backlog[i];
            if (command.status != MTLCommandBufferStatusCompleted ||
                !(command.GPUStartTime > 0 && command.GPUEndTime > command.GPUStartTime)) return 10;
            printf("BACKLOG_GPU_INTERVAL %u start=%.9f end=%.9f\n", i, command.GPUStartTime, command.GPUEndTime);
        }
        printf("LATE_INTERLEAVING child_before_last_parent=%u parent_submissions=8\n",
            results[1].end < results[0].start);
        for (unsigned job = 0; job < 2; ++job) {
            if (!verify(&results[job], job ? 1 : 4000000, job ? 1 : 8)) return 10;
            printf("METAL_GPU_INTERVAL %u start=%.9f end=%.9f\n", job, results[job].start, results[job].end);
            printf("CLIENT_OUTPUT %u:", job);
            for (unsigned i = 0; i < 16; ++i) printf(" %08x", results[job].words[i]);
            putchar('\n');
        }
        puts("PASS: two independent Metal clients, all 32 output words and 128 guard bytes");
        puts("BACKLOG_MARKERS_PASS: all8 independently written job markers and both clients marker guards");
        if (!rearm(first, 1000000, 0)) return 2;
        printf("READY_RESUME before commit; gpu_output=0x%llx; size=160; pid=%d\n",
            (unsigned long long)first.output.gpuAddress, getpid());
        fflush(stdout); if (getchar() == EOF) return 9;
        [first.command commit]; Result resumed;
        if (!finish(first, &resumed) || !verify(&resumed, 1000000, 1)) return 10;
        printf("RESUME_GPU_INTERVAL start=%.9f end=%.9f\n", resumed.start, resumed.end);
        puts("RESUME_OUTPUT_PASS: all16 arithmetic words and64 guard bytes");
        puts("REPLAY READY: holding Metal resources; press Enter to release");
        fflush(stdout); if (getchar() == EOF) return 9;
        token = 'R'; if (!transfer(go[1], &token, 1, 1)) return 3;
        close(ready[0]); close(go[1]); close(done[0]);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 11;
    }
    return 0;
}
