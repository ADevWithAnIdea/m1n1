// SPDX-License-Identifier: MIT
// Two independent untracked ranges: determine whether tracked resource hazards
// caused the serial engine handoff in the otherwise identical reference.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef M4MAX_PAIR
#define M4MAX_PAIR 0
#endif
#ifndef M4MAX_TIMESTAMPS
#define M4MAX_TIMESTAMPS 0
#endif
#ifndef M4MAX_WARMUP
#define M4MAX_WARMUP 0
#endif
#ifndef M4MAX_TWO_QUEUES
#define M4MAX_TWO_QUEUES 0
#endif
#if M4MAX_TWO_QUEUES && (!M4MAX_PAIR || M4MAX_WARMUP)
#error Two-queue reference requires two submissions without warmups
#endif
#if M4MAX_WARMUP && (M4MAX_PAIR || M4MAX_TIMESTAMPS)
#error Warmup reference requires the ordinary single compute workload
#endif

int main(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) { fputs("No Metal device\n", stderr); return 2; }
        NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
            "kernel void fill(device uint *output [[buffer(0)]],"
            "constant uint &iterations [[buffer(1)]], uint tid [[thread_position_in_grid]]) {"
            "uint value=0x5a110000u^tid; for(uint j=0;j<iterations;j++)"
            "value=((value<<7)|(value>>25))+0x9e3779b9u+j; output[tid]=value; }";
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        if (!library) { NSLog(@"Metal compile: %@", error); return 3; }
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:
            [library newFunctionWithName:@"fill"] error:&error];
        if (!pipeline) { NSLog(@"Metal pipeline: %@", error); return 3; }
        const unsigned int submissions = M4MAX_PAIR ? 2 : 1;
        const unsigned int words_count = submissions*16;
        id<MTLBuffer> output = [device newBufferWithLength:128 options:MTLResourceStorageModeShared|MTLResourceHazardTrackingModeUntracked];
        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (!output || !queue) { fputs("Buffer/queue allocation failed\n", stderr); return 3; }
        id<MTLCommandQueue> second_queue = M4MAX_TWO_QUEUES ? [device newCommandQueue] : queue;
        if (!second_queue || (M4MAX_TWO_QUEUES && second_queue == queue)) return 3;
        memset(output.contents, 0xa5, 128);
        id<MTLCounterSampleBuffer> timestamps = nil;
        if (M4MAX_TIMESTAMPS) {
            MTLCounterSampleBufferDescriptor *descriptor = [MTLCounterSampleBufferDescriptor new];
            for (id<MTLCounterSet> set in device.counterSets) {
                if ([set.name isEqualToString:MTLCommonCounterSetTimestamp]) {
                    descriptor.counterSet = set; break;
                }
            }
            if (!descriptor.counterSet) { fputs("No timestamp counter set\n", stderr); return 6; }
            descriptor.storageMode = MTLStorageModeShared;
            descriptor.sampleCount = submissions*2;
            timestamps = [device newCounterSampleBufferWithDescriptor:descriptor error:&error];
            if (!timestamps) { NSLog(@"Timestamp buffer: %@", error); return 6; }
        }
        // Reuse this exact queue before arming the capture. Each native
        // submission must independently replace poison with all 16 words.
        // The final READY dispatch is captured by the ordinary held-kick hook.
        for (unsigned int warmup=0; warmup<M4MAX_WARMUP; ++warmup) {
            @autoreleasepool {
                memset(output.contents,0xa5,64);
                id<MTLCommandBuffer> command=[queue commandBuffer];
                id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
                if(!command || !encoder) return 3;
                [encoder setComputePipelineState:pipeline];
                [encoder setBuffer:output offset:0 atIndex:0];
                [encoder dispatchThreads:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(16,1,1)];
                [encoder endEncoding];[command commit];[command waitUntilCompleted];
                if(command.status!=MTLCommandBufferStatusCompleted) return 4;
                const unsigned int *words=output.contents;
                for(unsigned int i=0;i<16;i++) if(words[i]!=0x5a110000u+i) return 5;
            }
            printf("WARMUP %u/%u: all sixteen GPU output words PASS\n",warmup+1,(unsigned)M4MAX_WARMUP);
            fflush(stdout);
        }
        memset(output.contents,0xa5,128);
        NSMutableArray<id<MTLCommandBuffer>> *commands = [NSMutableArray array];
        for (unsigned int index=0; index<submissions; ++index) {
        id<MTLCommandBuffer> command = [(M4MAX_TWO_QUEUES && index ? second_queue : queue) commandBuffer];
        MTLComputePassDescriptor *pass = [MTLComputePassDescriptor computePassDescriptor];
        if (M4MAX_TIMESTAMPS) {
            pass.sampleBufferAttachments[0].sampleBuffer = timestamps;
            pass.sampleBufferAttachments[0].startOfEncoderSampleIndex = index*2;
            pass.sampleBufferAttachments[0].endOfEncoderSampleIndex = index*2+1;
        }
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoderWithDescriptor:pass];
        if (!command || !encoder) { fputs("Encoder allocation failed\n", stderr); return 3; }
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:output offset:index*64 atIndex:0];
        const uint32_t iterations=index?1:1000000;[encoder setBytes:&iterations length:sizeof(iterations) atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(16,1,1)];
        [encoder endEncoding];
        [commands addObject:command];
        }
        printf("READY before commit; gpu_output=0x%llx; cpu_output=%p; size=%u\n",
               (unsigned long long)output.gpuAddress, output.contents, 128u);
        fflush(stdout);
        getchar();
        // Publish both without waiting for the first. The hook suppresses
        // the first kick while macOS continues and captures the second kick.
        for (unsigned int index=0; index<submissions; ++index) {
            [commands[index] commit];
            // Let macOS publish the first kick before committing the second,
            // without waiting for GPU completion or releasing any resources.
            if (index+1<submissions) usleep(100000);
        }
        for (id<MTLCommandBuffer> command in commands) {
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            NSLog(@"Metal command: %@", command.error); return 4;
        }
        }
        for(unsigned i=0;i<submissions;i++) {
            printf("METAL_GPU_INTERVAL %u start=%.9f end=%.9f\n",i,commands[i].GPUStartTime,commands[i].GPUEndTime);
        }
        const unsigned int *words = output.contents;
        for (unsigned int i=0; i<words_count; ++i) {
            printf("%08x%s", words[i], i==words_count-1 ? "\n" : " ");
            uint32_t expected=0x5a110000U^(i%16);
            for(uint32_t j=0;j<(i<16?1000000U:1U);j++)expected=((expected<<7)|(expected>>25))+0x9e3779b9U+j;
            if(words[i]!=expected)return 5;
        }
        for(unsigned i=M4MAX_PAIR?128:64;i<128;i++)if(((unsigned char *)output.contents)[i]!=0xa5)return 5;
        puts(M4MAX_PAIR ? "PASS: Metal GPU changed all 32 output words" :
                         "PASS: Metal GPU changed all sixteen output words");
        if (M4MAX_TIMESTAMPS) {
            NSData *data = [timestamps resolveCounterRange:NSMakeRange(0,submissions*2)];
            if (data.length != submissions*2*sizeof(MTLCounterResultTimestamp)) return 6;
            const MTLCounterResultTimestamp *values = data.bytes;
            for (unsigned int index=0; index<submissions; ++index) {
                printf("TIMESTAMPS %u: start=0x%llx end=0x%llx\n", index,
                    (unsigned long long)values[index*2].timestamp,
                    (unsigned long long)values[index*2+1].timestamp);
                if (!values[index*2].timestamp || values[index*2].timestamp > values[index*2+1].timestamp) return 6;
            }
            puts("PASS: Metal timestamp samples are nonzero and ordered");
        }
        puts("REPLAY READY: holding Metal resources; press Enter to release");
        fflush(stdout);
        getchar();
    }
    return 0;
}
