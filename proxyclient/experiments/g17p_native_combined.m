// SPDX-License-Identifier: MIT
// Same retained R -> C258 -> R34 pressure workload as the failing UAPI case.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <errno.h>

extern char **environ;

static pid_t start_compute_worker(const char *executable, const char *shader, int *release_fd)
{
    int result_pipe[2], release_pipe[2];
    if (pipe(result_pipe) || pipe(release_pipe)) return -1;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, result_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, release_pipe[0], STDIN_FILENO);
    for (NSUInteger i = 0; i < 2; i++) {
        posix_spawn_file_actions_addclose(&actions, result_pipe[i]);
        posix_spawn_file_actions_addclose(&actions, release_pipe[i]);
    }
    char *arguments[] = {(char *)executable, (char *)shader, "--compute-worker", NULL};
    pid_t child = -1;
    int error = posix_spawn(&child, executable, &actions, NULL, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(result_pipe[1]); close(release_pipe[0]);
    if (error) { close(result_pipe[0]); close(release_pipe[1]); return -1; }
    FILE *results = fdopen(result_pipe[0], "r");
    if (!results) { close(result_pipe[0]); close(release_pipe[1]); return -1; }
    char line[1024];
    BOOL ready = NO;
    while (fgets(line, sizeof(line), results)) {
        fputs(line, stdout);
        if (!strcmp(line, "G17P_COMBINED_COMPUTE_ONLY_PASS retained=1\n")) {
            ready = YES; break;
        }
    }
    fclose(results);
    if (!ready) { close(release_pipe[1]); waitpid(child, NULL, 0); return -1; }
    *release_fd = release_pipe[1];
    return child;
}

static void checkpoint(const char *phase, NSUInteger index)
{
    printf("G17P_COMBINED_CHECKPOINT phase=%s index=%lu\n", phase, (unsigned long)index);
    FILE *console = fopen("/dev/console", "w");
    if (console) {
        fprintf(console, "G17P_COMBINED_CHECKPOINT phase=%s index=%lu\n", phase, (unsigned long)index);
        fprintf(console, "G17P_PARTIAL_ARM_CAPTURE\n");
        fclose(console);
    }
}

static BOOL check_images(NSArray<id<MTLBuffer>> *images, NSUInteger draw)
{
    BOOL exact = YES;
    for (NSUInteger target = 0; target < 8; target++) {
        const uint8_t *actual = images[target].contents;
        float value = 16384.0f * (float)(target + 1);
        NSUInteger bad = 0, first = NSUIntegerMax;
        for (NSUInteger at = 0; at < 0x10000; at++) {
            uint8_t expected = 0;
            if ((at >= 0x7f04 && at < 0x7f08) || (at >= 0x7f08 && at < 0x7f0c))
                expected = ((uint8_t *)&value)[at & 3];
            if (actual[at] != expected) {
                if (first == NSUIntegerMax) first = at;
                bad++;
            }
        }
        printf("G17P_COMBINED_IMAGE draw=%lu target=%lu bad=%lu first=%lu\n",
               (unsigned long)draw, (unsigned long)target, (unsigned long)bad, (unsigned long)first);
        exact &= bad == 0;
    }
    return exact;
}

int main(int argc, const char **argv)
{
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);
        if (argc != 2 && argc != 3) return 1;
        BOOL compute_only = argc == 3 && !strcmp(argv[2], "--compute-worker");
        BOOL separate_compute = argc == 3 && !strcmp(argv[2], "--separate-compute");
        if (argc == 3 && !compute_only && !separate_compute) return 1;
        pid_t worker = -1;
        int release_fd = -1;
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) { puts("G17P_COMBINED_NO_DEVICE"); return 2; }
        NSError *error = nil;
        NSString *source = [NSString stringWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]
                                                   encoding:NSUTF8StringEncoding error:&error];
        id<MTLLibrary> library = source ? [device newLibraryWithSource:source options:nil error:&error] : nil;
        if (!library) { printf("G17P_COMBINED_LIBRARY_ERROR %s\n", error.description.UTF8String); return 3; }
        MTLRenderPipelineDescriptor *descriptor = [MTLRenderPipelineDescriptor new];
        descriptor.vertexFunction = [library newFunctionWithName:@"partial_vertex"];
        descriptor.fragmentFunction = [library newFunctionWithName:@"partial_fragment_constant"];
        for (NSUInteger target = 0; target < 8; target++) {
            MTLRenderPipelineColorAttachmentDescriptor *color = descriptor.colorAttachments[target];
            color.pixelFormat = MTLPixelFormatR32Float;
            color.blendingEnabled = YES;
            color.rgbBlendOperation = color.alphaBlendOperation = MTLBlendOperationAdd;
            color.sourceRGBBlendFactor = color.destinationRGBBlendFactor = MTLBlendFactorOne;
            color.sourceAlphaBlendFactor = color.destinationAlphaBlendFactor = MTLBlendFactorOne;
        }
        id<MTLRenderPipelineState> render_pipeline = [device newRenderPipelineStateWithDescriptor:descriptor error:&error];
        if (!render_pipeline) { printf("G17P_COMBINED_RENDER_PIPELINE_ERROR %s\n", error.description.UTF8String); return 4; }
        id<MTLCommandQueue> queue = [device newCommandQueueWithMaxCommandBufferCount:64];
        NSMutableArray<id<MTLBuffer>> *images = [NSMutableArray new];
        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        for (NSUInteger target = 0; target < 8; target++) {
            id<MTLBuffer> image = [device newBufferWithLength:0x10000 options:MTLResourceStorageModeShared];
            if (!image) return 5;
            MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatR32Float
                                                                                     width:128 height:128 mipmapped:NO];
            td.storageMode = MTLStorageModeShared;
            td.usage = MTLTextureUsageRenderTarget;
            id<MTLTexture> texture = [image newTextureWithDescriptor:td offset:0 bytesPerRow:512];
            if (!texture) return 5;
            pass.colorAttachments[target].texture = texture;
            pass.colorAttachments[target].loadAction = MTLLoadActionClear;
            pass.colorAttachments[target].storeAction = MTLStoreActionStore;
            pass.colorAttachments[target].clearColor = MTLClearColorMake(0, 0, 0, 0);
            [images addObject:image];
            printf("G17P_COMBINED_RESOURCE image%lu=0x%llx size=0x10000\n", (unsigned long)target, (unsigned long long)image.gpuAddress);
        }
        id<MTLBuffer> varying = [device newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
        if (!queue || !varying) return 5;
        memset(varying.contents, 0, varying.length);
        NSMutableArray<id<MTLBuffer>> *inputs_a = [NSMutableArray new], *inputs_b = [NSMutableArray new], *outputs = [NSMutableArray new];
        for (NSUInteger lane = 0; lane < 56; lane++) {
            id<MTLBuffer> a = [device newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
            id<MTLBuffer> b = [device newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
            id<MTLBuffer> out = [device newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
            if (!a || !b || !out) return 5;
            memset(a.contents, 0, a.length); memset(b.contents, 0, b.length); memset(out.contents, 0xa5, out.length);
            for (NSUInteger element = 0; element < 64; element++) ((float *)b.contents)[element] = (float)(lane + 8) + 0.25f;
            [inputs_a addObject:a]; [inputs_b addObject:b]; [outputs addObject:out];
            printf("G17P_COMBINED_RESOURCE lane=%lu a=0x%llx b=0x%llx out=0x%llx size=0x4000\n", (unsigned long)lane,
                   (unsigned long long)a.gpuAddress, (unsigned long long)b.gpuAddress, (unsigned long long)out.gpuAddress);
        }
        NSMutableArray<id<MTLCommandBuffer>> *retained_commands = [NSMutableArray new];
        NSInteger epochs[56]; for (NSUInteger lane = 0; lane < 56; lane++) epochs[lane] = -1;
        id<MTLComputePipelineState> compute_pipeline = nil;
        for (NSUInteger draw = compute_only ? 1 : 0; draw < 34; draw++) {
            if (draw == 1) {
                if (separate_compute) {
                    worker = start_compute_worker(argv[0], argv[1], &release_fd);
                    if (worker < 0) { puts("G17P_COMBINED_WORKER_ERROR"); return 12; }
                } else {
                // Construct compute pipeline after the opening render, as the shim does.
                compute_pipeline = [device newComputePipelineStateWithFunction:[library newFunctionWithName:@"g17p_add"] error:&error];
                if (!compute_pipeline) { printf("G17P_COMBINED_COMPUTE_PIPELINE_ERROR %s\n", error.description.UTF8String); return 6; }
                for (NSUInteger first = 0, batch = 0; first < 258; first += 56, batch++) {
                    NSUInteger active = MIN((NSUInteger)56, (NSUInteger)258 - first);
                    NSMutableArray<id<MTLCommandBuffer>> *commands = [NSMutableArray new];
                    checkpoint("compute", batch);
                    for (NSUInteger lane = 0; lane < active; lane++) {
                        for (NSUInteger element = 0; element < 64; element++)
                            ((float *)inputs_a[lane].contents)[element] = (float)(2000 + (lane + 8) * 128 + batch * 8192 + element);
                        memset(outputs[lane].contents, 0xa5, outputs[lane].length);
                        id<MTLCommandBuffer> command = [queue commandBuffer];
                        command.label = [NSString stringWithFormat:@"combined compute %lu", (unsigned long)(first + lane)];
                        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                        [encoder setComputePipelineState:compute_pipeline];
                        [encoder setBuffer:inputs_a[lane] offset:0 atIndex:0];
                        [encoder setBuffer:inputs_b[lane] offset:0 atIndex:1];
                        [encoder setBuffer:outputs[lane] offset:0 atIndex:2];
                        [encoder dispatchThreads:MTLSizeMake(64, 1, 1) threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
                        [encoder endEncoding]; [command commit]; [commands addObject:command]; [retained_commands addObject:command];
                        epochs[lane] = (NSInteger)batch;
                    }
                    for (id<MTLCommandBuffer> command in commands) {
                        [command waitUntilCompleted];
                        if (command.status != MTLCommandBufferStatusCompleted) { printf("G17P_COMBINED_COMPUTE_ERROR %s\n", command.error.description.UTF8String); return 7; }
                    }
                    for (NSUInteger lane = 0; lane < 56; lane++) {
                        const uint8_t *bytes = outputs[lane].contents;
                        for (NSUInteger at = 0; at < 0x4000; at++) {
                            uint8_t expected = 0xa5;
                            if (epochs[lane] >= 0 && at < 256) {
                                float value = (float)(2000 + (lane + 8) * 129 + (NSUInteger)epochs[lane] * 8192 + at / 4) + 0.25f;
                                expected = ((uint8_t *)&value)[at & 3];
                            }
                            if (bytes[at] != expected) { printf("G17P_COMBINED_COMPUTE_IMAGE_FAIL batch=%lu lane=%lu byte=%lu\n", (unsigned long)batch, (unsigned long)lane, (unsigned long)at); return 8; }
                        }
                    }
                    printf("G17P_COMBINED_COMPUTE_PASS count=%lu guards=56\n", (unsigned long)(first + active));
                }
                }
                if (compute_only) {
                    // Hold every command/resource and this Metal context until
                    // the parent has checked all its resumed render images.
                    puts("G17P_COMBINED_COMPUTE_ONLY_PASS retained=1");
                    char release;
                    return read(STDIN_FILENO, &release, 1) == 1 && release == 'R' ? 0 : 13;
                }
                if (!check_images(images, 0)) return 9;
            }
            for (id<MTLBuffer> image in images) memset(image.contents, 0xa5, image.length);
            id<MTLCommandBuffer> command = [queue commandBuffer];
            command.label = [NSString stringWithFormat:@"combined render %lu", (unsigned long)draw];
            id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:pass];
            const uint32_t dimensions[] = {128, 128, 3, 131072};
            [encoder setRenderPipelineState:render_pipeline];
            [encoder setVertexBytes:dimensions length:sizeof(dimensions) atIndex:0];
            [encoder setVertexBuffer:varying offset:0 atIndex:1];
            [encoder setViewport:(MTLViewport){2, 0, 128, 128, 0, 1}];
            [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:131072 * 3];
            [encoder endEncoding]; checkpoint("render", draw); [command commit]; [retained_commands addObject:command];
            [command waitUntilCompleted];
            if (command.status != MTLCommandBufferStatusCompleted) { printf("G17P_COMBINED_RENDER_ERROR %s\n", command.error.description.UTF8String); return 10; }
            if (!check_images(images, draw)) return 11;
            printf("G17P_COMBINED_RENDER_PASS draw=%lu gpu_start=%.9f gpu_end=%.9f\n", (unsigned long)draw, command.GPUStartTime, command.GPUEndTime);
        }
        if (separate_compute) {
            int status = 0;
            if (write(release_fd, "R", 1) != 1) return 14;
            close(release_fd);
            pid_t waited;
            do { waited = waitpid(worker, &status, 0); } while (waited < 0 && errno == EINTR);
            if (waited != worker || !WIFEXITED(status) || WEXITSTATUS(status)) return 15;
            puts("G17P_COMBINED_SEPARATE_CONTEXT_PASS retained_worker=1");
        }
        puts("G17P_COMBINED_PASS computes=258 renders=34 full_images=8 retained=1");
        return 0;
    }
}
