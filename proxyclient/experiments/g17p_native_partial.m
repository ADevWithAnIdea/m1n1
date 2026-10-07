// SPDX-License-Identifier: MIT
// Own-source Metal workload that deliberately overflows the tiled vertex buffer.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

enum {
    attachment_count = 8,
    default_width = 512,
    default_height = 512,
};

static FILE *open_console(void)
{
    FILE *console = fopen("/dev/console", "w");
    if (console != NULL)
        setvbuf(console, NULL, _IONBF, 0);
    return console;
}

static const char *error_string(NSError *error)
{
    if (error == nil)
        return "none";
    return [[error localizedDescription] UTF8String];
}

static BOOL parse_dimension(const char *text, NSUInteger *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > 4096)
        return NO;
    *value = parsed;
    return YES;
}

static BOOL parse_triangle_count(const char *text, NSUInteger *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > UINT32_MAX / 3)
        return NO;
    *value = (NSUInteger)parsed;
    return YES;
}

static BOOL parse_submission_count(const char *text, NSUInteger *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > NSUIntegerMax)
        return NO;
    *value = (NSUInteger)parsed;
    return YES;
}

static NSString *library_path(const char *argv0)
{
    NSString *executable = [NSString stringWithUTF8String:argv0];
    if (![executable isAbsolutePath]) {
        executable = [[[NSFileManager defaultManager] currentDirectoryPath]
            stringByAppendingPathComponent:executable];
    }
    executable = [executable stringByStandardizingPath];
    return [[executable stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:@"g17ppartial.metallib"];
}

static uint8_t component_value(NSUInteger x, NSUInteger y,
                               NSUInteger attachment, NSUInteger component)
{
    NSUInteger value;
    switch (component) {
    case 0:
        value = x + attachment * 17;
        break;
    case 1:
        value = y + attachment * 29;
        break;
    default:
        value = (x ^ y) + attachment * 43;
        break;
    }
    return 1 + value % 253;
}

static void list_counters(id<MTLDevice> device)
{
    printf("G17P_PARTIAL_COUNTER_SETS=%lu\n",
           (unsigned long)[[device counterSets] count]);
    for (id<MTLCounterSet> set in [device counterSets]) {
        printf("G17P_PARTIAL_COUNTER_SET name=%s count=%lu\n",
               [[set name] UTF8String], (unsigned long)[[set counters] count]);
        for (id<MTLCounter> counter in [set counters])
            printf("G17P_PARTIAL_COUNTER name=%s\n",
                   [[counter name] UTF8String]);
    }
}

static BOOL validate_independent_accumulation(
    NSArray<NSArray<id<MTLBuffer>> *> *sets, NSUInteger completed, FILE *console,
    float constant_scale, NSUInteger x_shift)
{
    BOOL exact = YES;
    for (NSUInteger set = 0; set < [sets count]; ++set) {
        for (NSUInteger attachment = 0; attachment < attachment_count; ++attachment) {
            id<MTLBuffer> output = sets[set][attachment];
            const uint8_t *bytes = [output contents];
            BOOL valid = [output length] == 0x10000;
            for (NSUInteger offset = 0; valid && offset < [output length];) {
                if (set < completed && (offset == 0x7efc + x_shift * 4 ||
                                        offset == 0x7f00 + x_shift * 4)) {
                    float value;
                    memcpy(&value, bytes + offset, sizeof(value));
                    float expected = (float)(attachment + 1) * constant_scale;
                    valid = constant_scale != 1.0f ? value == expected :
                        isfinite(value) && fabsf(value - expected) < 0.02f;
                    offset += sizeof(value);
                } else {
                    valid = bytes[offset++] == 0;
                }
            }
            if (!valid) {
                fprintf(stderr, "G17P_PARTIAL_FULL_OUTPUT_FAIL set=%lu attachment=%lu completed=%lu\n",
                        (unsigned long)set, (unsigned long)attachment, (unsigned long)completed);
                exact = NO;
            }
        }
    }
    printf("G17P_PARTIAL_FULL_OUTPUT_CHECK completed=%lu sets=%lu exact=%d\n",
           (unsigned long)completed, (unsigned long)[sets count], exact);
    if (console != NULL)
        fprintf(console, "G17P_PARTIAL_FULL_OUTPUT_CHECK completed=%lu sets=%lu exact=%d\n",
                (unsigned long)completed, (unsigned long)[sets count], exact);
    return exact;
}

static BOOL validate_vertex_observations(id<MTLBuffer> buffer, FILE *console,
                                         BOOL observe_fragments)
{
    const NSUInteger vertices = 24, words = 9;
    const uint8_t *body = [buffer contents];
    BOOL exact = [buffer length] == 0x4000;
    NSUInteger bad_words = 0, outside_bytes = 0;
    for (NSUInteger vertex = 0; vertex < vertices; ++vertex) {
        for (NSUInteger component = 0; component < words; ++component) {
            float value;
            memcpy(&value, body + (vertex * words + component) * sizeof(float), sizeof(value));
            float expected = component == 0 ? (float)(vertex + 1) : (float)component / 8.0f;
            bad_words += !isfinite(value) || value != expected;
        }
    }
    for (NSUInteger offset = vertices * words * sizeof(float); offset < [buffer length]; ++offset) {
        if (observe_fragments && offset >= 0x400 && offset < 0x640)
            continue;
        outside_bytes += body[offset] != 0;
    }
    exact &= bad_words == 0 && outside_bytes == 0;
    printf("G17P_VERTEX_OBSERVATION_CHECK vertices=24 bad_words=%lu outside_bytes=%lu exact=%d\n",
           (unsigned long)bad_words, (unsigned long)outside_bytes, exact);
    if (console != NULL)
        fprintf(console, "G17P_VERTEX_OBSERVATION_CHECK vertices=24 bad_words=%lu outside_bytes=%lu exact=%d\n",
                (unsigned long)bad_words, (unsigned long)outside_bytes, exact);
    if (observe_fragments) {
        NSUInteger fragment_bad_words = 0;
        for (NSUInteger record = 0; record < 16; ++record) {
            for (NSUInteger component = 0; component < words; ++component) {
                float value;
                memcpy(&value, body + 0x400 + (record * words + component) * sizeof(float),
                       sizeof(value));
                float expected = component == 0 ? (float)(record / 2 + 1) : (float)component / 8.0f;
                fragment_bad_words += !isfinite(value) || value != expected;
            }
        }
        printf("G17P_FRAGMENT_OBSERVATION_CHECK records=16 bad_words=%lu exact=%d\n",
               (unsigned long)fragment_bad_words, fragment_bad_words == 0);
        if (console != NULL)
            fprintf(console, "G17P_FRAGMENT_OBSERVATION_CHECK records=16 bad_words=%lu exact=%d\n",
                    (unsigned long)fragment_bad_words, fragment_bad_words == 0);
        exact &= fragment_bad_words == 0;
    }
    return exact;
}

int main(int argc, const char **argv)
{
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);

        NSUInteger width = default_width;
        NSUInteger height = default_height;
        BOOL concentrated = argc >= 4 && strcmp(argv[3], "concentrated") == 0;
        BOOL overflow = argc >= 4 && strcmp(argv[3], "overflow") == 0;
        BOOL accumulate = argc >= 4 && strcmp(argv[3], "accumulate") == 0;
        BOOL indirect = argc >= 4 && strcmp(argv[3], "indirect") == 0;
        BOOL counter_only = argc == 2 && strcmp(argv[1], "--list-counters") == 0;
        if (!counter_only && argc > 1 && !parse_dimension(argv[1], &width)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR width\n");
            return 1;
        }
        if (!counter_only && argc > 2 && !parse_dimension(argv[2], &height)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR height\n");
            return 1;
        }
        if (!counter_only && argc > 6) {
            fprintf(stderr, "G17P_PARTIAL_ERROR arguments\n");
            return 1;
        }
        if (!counter_only && argc >= 4 && !concentrated && !overflow &&
            !accumulate && !indirect) {
            fprintf(stderr, "G17P_PARTIAL_ERROR mode\n");
            return 1;
        }
        if (!counter_only && argc >= 5 && !overflow && !accumulate &&
            !indirect) {
            fprintf(stderr, "G17P_PARTIAL_ERROR triangle-count-mode\n");
            return 1;
        }

        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            fprintf(stderr, "G17P_PARTIAL_ERROR no-device\n");
            return 2;
        }
        if (counter_only) {
            list_counters(device);
            return 0;
        }

        const NSUInteger pixel_count = width * height;
        NSUInteger triangle_count = pixel_count;
        NSUInteger submission_count = 1;
        NSUInteger command_queue_count = 1;
        if ((overflow || accumulate || indirect) && argc >= 5 &&
            !parse_triangle_count(argv[4], &triangle_count)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR triangle-count\n");
            return 1;
        }
        const char *submission_text = argc == 6 ? argv[5] :
            getenv("G17P_PARTIAL_SUBMISSIONS");
        if (submission_text != NULL &&
            !parse_submission_count(submission_text, &submission_count)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR submission-count\n");
            return 1;
        }
        const BOOL warmup_first_queue =
            getenv("G17P_WARMUP_FIRST_QUEUE") != NULL;
        const char *queue_count_text = getenv("G17P_COMMAND_QUEUE_COUNT");
        if (queue_count_text != NULL &&
            (!parse_submission_count(queue_count_text, &command_queue_count) ||
             command_queue_count >
                 submission_count + (warmup_first_queue ? 1 : 0))) {
            fprintf(stderr, "G17P_PARTIAL_ERROR command-queue-count\n");
            return 1;
        }
        const BOOL enqueue_all = getenv("G17P_ENQUEUE_ALL") != NULL;
        const BOOL encode_all_in_one =
            getenv("G17P_ENCODE_ALL_IN_ONE") != NULL;
        NSUInteger enqueue_batch_size = 0;
        const char *enqueue_batch_text = getenv("G17P_ENQUEUE_BATCH_SIZE");
        if (enqueue_batch_text != NULL &&
            (!parse_submission_count(enqueue_batch_text,
                                     &enqueue_batch_size) ||
             !enqueue_all || enqueue_batch_size >= submission_count)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR enqueue-batch-size\n");
            return 1;
        }
        const BOOL separate_queue_targets =
            getenv("G17P_SEPARATE_QUEUE_TARGETS") != NULL;
        const BOOL separate_submission_targets =
            getenv("G17P_SEPARATE_SUBMISSION_TARGETS") != NULL;
        const BOOL constant_pressure = getenv("G17P_CONSTANT_PRESSURE") != NULL;
        if (constant_pressure && (!accumulate || !separate_submission_targets ||
                                  triangle_count != 131072 || getenv("G17P_TINY_PREFIX_COUNT") != NULL)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR constant-pressure-layout\n");
            return 1;
        }
        if (separate_submission_targets &&
            (!accumulate || width != 128 || height != 128 ||
             (!constant_pressure && triangle_count != 1 && triangle_count != 8 && triangle_count != 48217) ||
             separate_queue_targets || encode_all_in_one || warmup_first_queue)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR independent-target-oracle-layout\n");
            return 1;
        }
        NSUInteger tiny_prefix_count = 0;
        const char *tiny_prefix_text = getenv("G17P_TINY_PREFIX_COUNT");
        if (tiny_prefix_text != NULL &&
            (!parse_submission_count(tiny_prefix_text, &tiny_prefix_count) ||
             tiny_prefix_count >= submission_count ||
             !separate_submission_targets || triangle_count != 48217)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR tiny-prefix-layout\n");
            return 1;
        }
        NSUInteger capture_after = 0;
        const char *capture_after_text = getenv("G17P_CAPTURE_AFTER");
        if (capture_after_text != NULL &&
            (!parse_submission_count(capture_after_text, &capture_after) ||
             capture_after >= submission_count)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR capture-after\n");
            return 1;
        }
        if (encode_all_in_one &&
            (command_queue_count != 1 || !enqueue_all || capture_after != 0 ||
             separate_queue_targets || enqueue_batch_size != 0)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR encode-all-in-one\n");
            return 1;
        }
        const char *observe_text = getenv("G17P_OBSERVE_VERTEX_OUTPUTS");
        const BOOL observe_vertices = observe_text != NULL && strcmp(observe_text, "1") == 0;
        const char *observe_fragment_text = getenv("G17P_OBSERVE_FRAGMENT_INPUTS");
        const BOOL observe_fragments = observe_fragment_text != NULL &&
                                      strcmp(observe_fragment_text, "1") == 0;
        if (observe_fragments && !observe_vertices) {
            fprintf(stderr, "G17P_PARTIAL_ERROR fragment-observation-requires-vertex-observation\n");
            return 1;
        }
        if (observe_vertices && (!accumulate || width != 128 || height != 128 ||
                                 triangle_count != 8 || submission_count != 1 ||
                                 command_queue_count != 1 || warmup_first_queue ||
                                 getenv("G17P_LOAD_EXISTING") != NULL)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR vertex-observation-layout\n");
            return 1;
        }
        const NSUInteger vertex_count = triangle_count * 3;
        const NSUInteger varying_count = vertex_count * attachment_count;
        if (pixel_count / width != height ||
            vertex_count / 3 != triangle_count ||
            varying_count / attachment_count != vertex_count ||
            varying_count > NSUIntegerMax / (4 * sizeof(float))) {
            fprintf(stderr, "G17P_PARTIAL_ERROR size-overflow\n");
            return 3;
        }
        const NSUInteger varying_size = observe_vertices ? 0x4000 : (overflow || accumulate || indirect) ?
            4 * sizeof(float) :
            varying_count * 4 * sizeof(float);
        const NSUInteger bytes_per_row = (width * 4 + 255) & ~255UL;
        const NSUInteger output_size = bytes_per_row * height;

        FILE *console = open_console();
        printf("G17P_PARTIAL_START pid=%d device=%s width=%lu height=%lu "
               "triangles=%lu vertices=%lu varying_bytes=%lu submissions=%lu "
               "command_queues=%lu enqueue_all=%d warmup_first_queue=%d "
               "separate_queue_targets=%d mode=%s\n",
               getpid(), [[device name] UTF8String], (unsigned long)width,
               (unsigned long)height, (unsigned long)triangle_count,
               (unsigned long)vertex_count, (unsigned long)varying_size,
               (unsigned long)submission_count,
               (unsigned long)command_queue_count, enqueue_all,
               warmup_first_queue, separate_queue_targets,
               accumulate ? "accumulate" : (indirect ? "indirect" :
                   (overflow ? "overflow" :
                    (concentrated ? "concentrated" : "distributed"))));
        if (console != NULL)
            fprintf(console,
                    "G17P_PARTIAL_START pid=%d width=%lu height=%lu "
                    "triangles=%lu varying_bytes=%lu submissions=%lu "
                    "command_queues=%lu enqueue_all=%d "
                    "warmup_first_queue=%d separate_queue_targets=%d "
                    "mode=%s\n",
                    getpid(), (unsigned long)width, (unsigned long)height,
                    (unsigned long)triangle_count, (unsigned long)varying_size,
                    (unsigned long)submission_count,
                    (unsigned long)command_queue_count, enqueue_all,
                    warmup_first_queue, separate_queue_targets,
                    accumulate ? "accumulate" : (indirect ? "indirect" :
                        (overflow ? "overflow" :
                         (concentrated ? "concentrated" : "distributed"))));

        NSError *error = nil;
        // Compile only our explicitly supplied Metal source on the target when
        // an offline Metal compiler is unavailable on the host. The normal
        // precompiled-library path and fragment entry point remain defaults.
        const char *source_path = getenv("G17P_PARTIAL_METAL_SOURCE");
        const char *fragment_name = getenv("G17P_PARTIAL_FRAGMENT");
        if (fragment_name == NULL)
            fragment_name = "partial_fragment";
        if (observe_vertices && strcmp(fragment_name, observe_fragments ?
                "partial_fragment_observed" : "partial_fragment_biased") != 0) {
            fprintf(stderr, "G17P_PARTIAL_ERROR vertex-observation-requires-biased-fragment\n");
            return 4;
        }
        if (strcmp(fragment_name, "partial_fragment") != 0 &&
            strcmp(fragment_name, "partial_fragment_one_varying") != 0 &&
            strcmp(fragment_name, "partial_fragment_biased") != 0 &&
            strcmp(fragment_name, "partial_fragment_observed") != 0 &&
            strcmp(fragment_name, "partial_fragment_constant") != 0) {
            fprintf(stderr, "G17P_PARTIAL_ERROR unsupported fragment entry point\n");
            return 4;
        }
        if (strcmp(fragment_name, "partial_fragment_observed") == 0 && !observe_fragments) {
            fprintf(stderr, "G17P_PARTIAL_ERROR fragment-observation-not-enabled\n");
            return 4;
        }
        if (constant_pressure && strcmp(fragment_name, "partial_fragment_constant") != 0) {
            fprintf(stderr, "G17P_PARTIAL_ERROR constant-pressure-fragment\n");
            return 4;
        }
        if (!constant_pressure && (strcmp(fragment_name, "partial_fragment_constant") == 0 ||
             strcmp(fragment_name, "partial_fragment_biased") == 0) &&
            (!accumulate || triangle_count != 8)) {
            fprintf(stderr, "G17P_PARTIAL_ERROR constant/biased witness requires eight triangles\n");
            return 4;
        }
        NSURL *url = [NSURL fileURLWithPath:source_path != NULL ?
            [NSString stringWithUTF8String:source_path] : library_path(argv[0])];
        printf("G17P_PARTIAL_LIBRARY_BEGIN path=%s\n", [[url path] UTF8String]);
        if (console != NULL)
            fprintf(console, "G17P_PARTIAL_LIBRARY_BEGIN path=%s\n",
                    [[url path] UTF8String]);
        id<MTLLibrary> library = nil;
        if (source_path != NULL) {
            NSString *source = [NSString stringWithContentsOfURL:url
                encoding:NSUTF8StringEncoding error:&error];
            if (source != nil)
                library = [device newLibraryWithSource:source options:nil error:&error];
        } else {
            library = [device newLibraryWithURL:url error:&error];
        }
        if (library == nil) {
            fprintf(stderr, "G17P_PARTIAL_ERROR library path=%s error=%s\n",
                    [[[url path] stringByStandardizingPath] UTF8String],
                    error_string(error));
            if (console != NULL)
                fprintf(console, "G17P_PARTIAL_ERROR library error=%s\n",
                        error_string(error));
            return 4;
        }
        printf("G17P_PARTIAL_LIBRARY_READY source=%d fragment=%s\n",
               source_path != NULL, fragment_name);
        if (console != NULL)
            fprintf(console, "G17P_PARTIAL_LIBRARY_READY source=%d fragment=%s\n",
                    source_path != NULL, fragment_name);

        MTLRenderPipelineDescriptor *pipeline_desc =
            [[MTLRenderPipelineDescriptor alloc] init];
        pipeline_desc.vertexFunction =
            [library newFunctionWithName:observe_vertices ? @"partial_vertex_observed" : @"partial_vertex"];
        pipeline_desc.fragmentFunction =
            [library newFunctionWithName:[NSString stringWithUTF8String:fragment_name]];
        for (NSUInteger i = 0; i < attachment_count; ++i) {
            pipeline_desc.colorAttachments[i].pixelFormat = accumulate ?
                MTLPixelFormatR32Float : MTLPixelFormatBGRA8Unorm;
            if (overflow || accumulate || indirect) {
                pipeline_desc.colorAttachments[i].blendingEnabled = YES;
                pipeline_desc.colorAttachments[i].rgbBlendOperation =
                    MTLBlendOperationAdd;
                pipeline_desc.colorAttachments[i].alphaBlendOperation =
                    MTLBlendOperationAdd;
                pipeline_desc.colorAttachments[i].sourceRGBBlendFactor =
                    MTLBlendFactorOne;
                pipeline_desc.colorAttachments[i].destinationRGBBlendFactor =
                    MTLBlendFactorOne;
                pipeline_desc.colorAttachments[i].sourceAlphaBlendFactor =
                    MTLBlendFactorOne;
                pipeline_desc.colorAttachments[i].destinationAlphaBlendFactor =
                    MTLBlendFactorOne;
            }
        }
        printf("G17P_PARTIAL_PIPELINE_BEGIN\n");
        id<MTLRenderPipelineState> pipeline =
            [device newRenderPipelineStateWithDescriptor:pipeline_desc error:&error];
        if (pipeline == nil) {
            fprintf(stderr, "G17P_PARTIAL_ERROR pipeline error=%s\n",
                    error_string(error));
            if (console != NULL)
                fprintf(console, "G17P_PARTIAL_ERROR pipeline error=%s\n",
                        error_string(error));
            return 5;
        }
        printf("G17P_PARTIAL_PIPELINE_READY\n");

        id<MTLBuffer> varyings =
            [device newBufferWithLength:varying_size
                                options:MTLResourceStorageModeShared];
        if (varyings == nil) {
            fprintf(stderr, "G17P_PARTIAL_ERROR varying-buffer bytes=%lu\n",
                    (unsigned long)varying_size);
            if (console != NULL)
                fprintf(console,
                        "G17P_PARTIAL_ERROR varying-buffer bytes=%lu\n",
                        (unsigned long)varying_size);
            return 6;
        }
        float *varying_data = [varyings contents];
        if (observe_vertices) {
            memset(varying_data, 0, varying_size);
            printf("G17P_VERTEX_OBSERVATION_BUFFER address=0x%llx size=0x%lx\n",
                   (unsigned long long)[varyings gpuAddress], (unsigned long)varying_size);
            if (console != NULL)
                fprintf(console, "G17P_VERTEX_OBSERVATION_BUFFER address=0x%llx size=0x%lx\n",
                        (unsigned long long)[varyings gpuAddress], (unsigned long)varying_size);
        }
        for (NSUInteger vertex = 0;
             !overflow && !accumulate && !indirect && vertex < vertex_count;
             ++vertex) {
            const NSUInteger pixel = vertex / 3;
            const NSUInteger x = pixel % width;
            const NSUInteger y = pixel / width;
            for (NSUInteger attachment = 0; attachment < attachment_count;
                 ++attachment) {
                const NSUInteger base = (vertex * attachment_count + attachment) * 4;
                varying_data[base + 0] =
                    component_value(x, y, attachment, 0) / 255.0f;
                varying_data[base + 1] =
                    component_value(x, y, attachment, 1) / 255.0f;
                varying_data[base + 2] =
                    component_value(x, y, attachment, 2) / 255.0f;
                varying_data[base + 3] = 1.0f;
            }
        }

        const NSUInteger target_set_count =
            separate_submission_targets ? submission_count :
            separate_queue_targets ? command_queue_count : 1;
        NSMutableArray<NSArray<id<MTLBuffer>> *> *output_sets =
            [NSMutableArray arrayWithCapacity:target_set_count];
        NSMutableArray<MTLRenderPassDescriptor *> *passes =
            [NSMutableArray arrayWithCapacity:target_set_count];
        const BOOL load_existing = getenv("G17P_LOAD_EXISTING") != NULL;
        for (NSUInteger target_set = 0; target_set < target_set_count;
             ++target_set) {
            NSMutableArray<id<MTLBuffer>> *outputs =
                [NSMutableArray arrayWithCapacity:attachment_count];
            MTLRenderPassDescriptor *pass =
                [MTLRenderPassDescriptor renderPassDescriptor];
            for (NSUInteger i = 0; i < attachment_count; ++i) {
                id<MTLBuffer> output =
                    [device newBufferWithLength:output_size
                                        options:MTLResourceStorageModeShared];
                if (output == nil) {
                    fprintf(stderr,
                            "G17P_PARTIAL_ERROR output-buffer set=%lu "
                            "index=%lu\n", (unsigned long)target_set,
                            (unsigned long)i);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ERROR output-buffer set=%lu "
                                "index=%lu\n", (unsigned long)target_set,
                                (unsigned long)i);
                    return 7;
                }
                memset([output contents], 0, output_size);
                MTLTextureDescriptor *texture_desc =
                    [MTLTextureDescriptor
                        texture2DDescriptorWithPixelFormat:(accumulate ?
                            MTLPixelFormatR32Float : MTLPixelFormatBGRA8Unorm)
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
                    fprintf(stderr,
                            "G17P_PARTIAL_ERROR output-texture set=%lu "
                            "index=%lu\n", (unsigned long)target_set,
                            (unsigned long)i);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ERROR output-texture set=%lu "
                                "index=%lu\n", (unsigned long)target_set,
                                (unsigned long)i);
                    return 8;
                }
                [outputs addObject:output];
                pass.colorAttachments[i].texture = target;
                pass.colorAttachments[i].loadAction = load_existing ?
                    MTLLoadActionLoad : MTLLoadActionClear;
                pass.colorAttachments[i].storeAction = MTLStoreActionStore;
                pass.colorAttachments[i].clearColor =
                    MTLClearColorMake(0, 0, 0, 0);
            }
            [output_sets addObject:outputs];
            [passes addObject:pass];
        }

        NSMutableArray<id<MTLCommandQueue>> *queues =
            [NSMutableArray arrayWithCapacity:command_queue_count];
        for (NSUInteger i = 0; i < command_queue_count; ++i) {
            // The default queue may cap the CPU at two committed buffers.
            // A held-doorbell capture deliberately keeps those two pending
            // while encoding the third publication, so request enough host
            // command-buffer slots for the complete enqueue-all batch.
            id<MTLCommandQueue> queue = enqueue_all ?
                [device newCommandQueueWithMaxCommandBufferCount:
                    submission_count] :
                [device newCommandQueue];
            if (queue == nil) {
                fprintf(stderr,
                        "G17P_PARTIAL_ERROR command-queue index=%lu\n",
                        (unsigned long)i);
                return 10;
            }
            [queues addObject:queue];
        }
        id<MTLBuffer> indirect_args = nil;
        if (indirect) {
            indirect_args = [device newBufferWithLength:4 * sizeof(uint32_t)
                                                options:MTLResourceStorageModeShared];
            if (indirect_args == nil) {
                fprintf(stderr, "G17P_PARTIAL_ERROR indirect-buffer\n");
                return 10;
            }
            uint32_t *args = [indirect_args contents];
            args[0] = (uint32_t)vertex_count;
            args[1] = 1;
            args[2] = 0;
            args[3] = 0;
        }
        uint32_t dimensions[4] = {
            (uint32_t)width, (uint32_t)height,
            accumulate ? 3u : ((overflow || indirect) ? 2u :
                (concentrated ? 1u : 0u)),
            (uint32_t)triangle_count,
        };
        MTLViewport viewport = {0, 0, width, height, 0, 1};
        if (constant_pressure)
            viewport.originX = 2;  // Match the qualified shim pressure witness.
        if (warmup_first_queue) {
            if (command_queue_count < 2) {
                fprintf(stderr,
                        "G17P_PARTIAL_ERROR warmup-requires-two-queues\n");
                return 11;
            }

            const NSUInteger warm_width = 64;
            const NSUInteger warm_height = 64;
            const NSUInteger warm_bytes_per_row = 256;
            const NSUInteger warm_output_size =
                warm_bytes_per_row * warm_height;
            id<MTLBuffer> warm_outputs[attachment_count] = { nil };
            id<MTLTexture> warm_targets[attachment_count] = { nil };
            MTLRenderPassDescriptor *warm_pass =
                [MTLRenderPassDescriptor renderPassDescriptor];
            for (NSUInteger i = 0; i < attachment_count; ++i) {
                warm_outputs[i] =
                    [device newBufferWithLength:warm_output_size
                                        options:MTLResourceStorageModeShared];
                if (warm_outputs[i] == nil) {
                    fprintf(stderr,
                            "G17P_PARTIAL_ERROR warmup-output index=%lu\n",
                            (unsigned long)i);
                    return 11;
                }
                memset([warm_outputs[i] contents], 0, warm_output_size);
                MTLTextureDescriptor *warm_texture_desc =
                    [MTLTextureDescriptor
                        texture2DDescriptorWithPixelFormat:(accumulate ?
                            MTLPixelFormatR32Float : MTLPixelFormatBGRA8Unorm)
                                                     width:warm_width
                                                    height:warm_height
                                                 mipmapped:NO];
                warm_texture_desc.usage = MTLTextureUsageRenderTarget;
                warm_texture_desc.storageMode = MTLStorageModeShared;
                warm_targets[i] =
                    [warm_outputs[i]
                        newTextureWithDescriptor:warm_texture_desc
                                           offset:0
                                      bytesPerRow:warm_bytes_per_row];
                if (warm_targets[i] == nil) {
                    fprintf(stderr,
                            "G17P_PARTIAL_ERROR warmup-texture index=%lu\n",
                            (unsigned long)i);
                    return 11;
                }
                warm_pass.colorAttachments[i].texture = warm_targets[i];
                warm_pass.colorAttachments[i].loadAction = MTLLoadActionClear;
                warm_pass.colorAttachments[i].storeAction = MTLStoreActionStore;
                warm_pass.colorAttachments[i].clearColor =
                    MTLClearColorMake(0, 0, 0, 0);
            }

            uint32_t warm_dimensions[4] = {
                (uint32_t)warm_width, (uint32_t)warm_height, 3, 1,
            };
            MTLViewport warm_viewport = {
                0, 0, warm_width, warm_height, 0, 1,
            };
            id<MTLCommandBuffer> warm_command = [queues[0] commandBuffer];
            id<MTLRenderCommandEncoder> warm_encoder =
                [warm_command renderCommandEncoderWithDescriptor:warm_pass];
            [warm_encoder setRenderPipelineState:pipeline];
            [warm_encoder setVertexBytes:warm_dimensions
                                  length:sizeof(warm_dimensions)
                                 atIndex:0];
            [warm_encoder setVertexBuffer:varyings offset:0 atIndex:1];
            [warm_encoder setViewport:warm_viewport];
            [warm_encoder drawPrimitives:MTLPrimitiveTypeTriangle
                             vertexStart:0
                             vertexCount:3];
            [warm_encoder endEncoding];
            printf("G17P_PARTIAL_WARMUP_READY queue=1/%lu width=%lu "
                   "height=%lu triangles=1\n",
                   (unsigned long)command_queue_count,
                   (unsigned long)warm_width, (unsigned long)warm_height);
            if (console != NULL)
                fprintf(console,
                        "G17P_PARTIAL_WARMUP_READY queue=1/%lu width=%lu "
                        "height=%lu triangles=1\n",
                        (unsigned long)command_queue_count,
                        (unsigned long)warm_width,
                        (unsigned long)warm_height);
            [warm_command commit];
            [warm_command waitUntilCompleted];
            printf("G17P_PARTIAL_WARMUP_DONE status=%ld error=%s\n",
                   (long)[warm_command status],
                   error_string([warm_command error]));
            if (console != NULL)
                fprintf(console,
                        "G17P_PARTIAL_WARMUP_DONE status=%ld error=%s\n",
                        (long)[warm_command status],
                        error_string([warm_command error]));
            if ([warm_command status] != MTLCommandBufferStatusCompleted)
                return 11;
        }
        BOOL exact = YES;
        NSUInteger completed_submissions = 0;
        MTLCommandBufferStatus last_status = MTLCommandBufferStatusNotEnqueued;
        NSError *last_error = nil;
        NSMutableArray<id<MTLCommandBuffer>> *submitted_commands =
            [NSMutableArray arrayWithCapacity:submission_count];
        id<MTLCommandBuffer> shared_command = encode_all_in_one ?
            [queues[0] commandBuffer] : nil;
        for (NSUInteger submission = 0; submission < submission_count;
             ++submission) {
            @autoreleasepool {
                if (!separate_submission_targets && (!enqueue_all || submission == 0)) {
                    for (NSArray<id<MTLBuffer>> *outputs in output_sets)
                        for (id<MTLBuffer> output in outputs)
                            memset([output contents], 0, output_size);
                }

                const NSUInteger queue_index =
                    (submission + (warmup_first_queue ? 1 : 0)) %
                    command_queue_count;
                const NSUInteger target_set =
                    separate_submission_targets ? submission :
                    separate_queue_targets ? queue_index : 0;
                id<MTLCommandBuffer> command = encode_all_in_one ?
                    shared_command : [queues[queue_index] commandBuffer];
                id<MTLRenderCommandEncoder> encoder =
                    [command renderCommandEncoderWithDescriptor:passes[target_set]];
                [encoder setRenderPipelineState:pipeline];
                const NSUInteger draw_triangles =
                    submission < tiny_prefix_count ? 1 : triangle_count;
                uint32_t draw_dimensions[4];
                memcpy(draw_dimensions, dimensions, sizeof(draw_dimensions));
                draw_dimensions[3] = (uint32_t)draw_triangles;
                [encoder setVertexBytes:draw_dimensions length:sizeof(draw_dimensions)
                                atIndex:0];
                [encoder setVertexBuffer:varyings offset:0 atIndex:1];
                if (observe_fragments)
                    [encoder setFragmentBuffer:varyings offset:0 atIndex:1];
                [encoder setViewport:viewport];
                if (indirect) {
                    [encoder drawPrimitives:MTLPrimitiveTypeTriangle
                              indirectBuffer:indirect_args
                        indirectBufferOffset:0];
                } else {
                    [encoder drawPrimitives:MTLPrimitiveTypeTriangle
                                vertexStart:0
                                vertexCount:draw_triangles * 3];
                }
                [encoder endEncoding];
                if (tiny_prefix_count) {
                    printf("G17P_PARTIAL_DRAW submission=%lu triangles=%lu\n",
                           (unsigned long)(submission + 1), (unsigned long)draw_triangles);
                    if (console != NULL)
                        fprintf(console, "G17P_PARTIAL_DRAW submission=%lu triangles=%lu\n",
                                (unsigned long)(submission + 1), (unsigned long)draw_triangles);
                }

                printf("G17P_PARTIAL_READY submission=%lu/%lu queue=%lu/%lu "
                       "input=0x%llx input_size=0x%lx output0=0x%llx "
                       "output_size=0x%lx target_set=%lu/%lu\n",
                       (unsigned long)(submission + 1),
                       (unsigned long)submission_count,
                       (unsigned long)(queue_index + 1),
                       (unsigned long)command_queue_count,
                       (unsigned long long)[varyings gpuAddress],
                       (unsigned long)varying_size,
                       (unsigned long long)[output_sets[target_set][0] gpuAddress],
                       (unsigned long)output_size,
                       (unsigned long)(target_set + 1),
                       (unsigned long)target_set_count);
                if (console != NULL)
                    fprintf(console,
                            "G17P_PARTIAL_READY submission=%lu/%lu "
                            "queue=%lu/%lu input=0x%llx input_size=0x%lx "
                            "output0=0x%llx output_size=0x%lx "
                            "target_set=%lu/%lu\n",
                            (unsigned long)(submission + 1),
                            (unsigned long)submission_count,
                            (unsigned long)(queue_index + 1),
                            (unsigned long)command_queue_count,
                            (unsigned long long)[varyings gpuAddress],
                            (unsigned long)varying_size,
                            (unsigned long long)
                                [output_sets[target_set][0] gpuAddress],
                            (unsigned long)output_size,
                            (unsigned long)(target_set + 1),
                            (unsigned long)target_set_count);

                if (encode_all_in_one && submission + 1 < submission_count) {
                    printf("G17P_PARTIAL_ENCODED submission=%lu/%lu\n",
                           (unsigned long)(submission + 1),
                           (unsigned long)submission_count);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ENCODED submission=%lu/%lu\n",
                                (unsigned long)(submission + 1),
                                (unsigned long)submission_count);
                    continue;
                }

                if (submission == 0 &&
                    getenv("G17P_STOP_BEFORE_COMMIT") != NULL) {
                    printf("G17P_PARTIAL_STOP_BEFORE_COMMIT pid=%d\n",
                           getpid());
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_STOP_BEFORE_COMMIT pid=%d\n",
                                getpid());
                    fflush(stdout);
                    fflush(stderr);
                    if (console != NULL)
                        fflush(console);
                    raise(SIGSTOP);
                }

                BOOL dump_before_commit =
                    getenv("G17P_DUMP_BEFORE_COMMIT") != NULL;
                BOOL dump_every_commit =
                    getenv("G17P_DUMP_EVERY_COMMIT") != NULL;
                if ((submission == 0 && dump_before_commit) ||
                    dump_every_commit) {
                    printf("G17P_PARTIAL_DUMP_BEFORE_COMMIT "
                           "submission=%lu/%lu\n",
                           (unsigned long)(submission + 1),
                           (unsigned long)submission_count);
                    kill(getpid(), SIGUSR1);
                    usleep(1000000);
                }

                if (submission == 0 &&
                    getenv("G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT") != NULL) {
                    printf("G17P_PARTIAL_ARM_CAPTURE next=1/%lu\n",
                           (unsigned long)submission_count);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ARM_CAPTURE next=1/%lu\n",
                                (unsigned long)submission_count);
                    fflush(stdout);
                    if (console != NULL)
                        fflush(console);
                }

                [command commit];
                [submitted_commands addObject:command];
                const BOOL intermediate_batch =
                    enqueue_batch_size != 0 &&
                    submission + 1 < submission_count &&
                    (submission + 1) % enqueue_batch_size == 0;
                if (enqueue_all && submission + 1 < submission_count &&
                    !intermediate_batch) {
                    printf("G17P_PARTIAL_ENQUEUED submission=%lu/%lu\n",
                           (unsigned long)(submission + 1),
                           (unsigned long)submission_count);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ENQUEUED submission=%lu/%lu\n",
                                (unsigned long)(submission + 1),
                                (unsigned long)submission_count);
                    continue;
                }
                [command waitUntilCompleted];
                if (observe_vertices && !validate_vertex_observations(varyings, console,
                                                                      observe_fragments))
                    return 13;
                if (enqueue_all) {
                    for (id<MTLCommandBuffer> submitted in submitted_commands)
                        [submitted waitUntilCompleted];
                }

                if (intermediate_batch) {
                    BOOL batch_completed = YES;
                    last_status = MTLCommandBufferStatusCompleted;
                    last_error = nil;
                    for (id<MTLCommandBuffer> submitted in submitted_commands) {
                        if ([submitted status] !=
                                MTLCommandBufferStatusCompleted) {
                            last_status = [submitted status];
                            last_error = [submitted error];
                            batch_completed = NO;
                        }
                    }
                    completed_submissions += [submitted_commands count];
                    printf("G17P_PARTIAL_BATCH_DONE submission=%lu/%lu "
                           "status=%ld error=%s completed=%d\n",
                           (unsigned long)(submission + 1),
                           (unsigned long)submission_count,
                           (long)last_status, error_string(last_error),
                           batch_completed);
                    [submitted_commands removeAllObjects];
                    if (!batch_completed)
                        exact = NO;
                    if (separate_submission_targets &&
                        !validate_independent_accumulation(output_sets,
                            completed_submissions, console,
                            constant_pressure ? (float)triangle_count / 8.0f : 1.0f,
                            constant_pressure ? 2 : 0))
                        return 12;
                    if (capture_after == submission + 1) {
                        printf("G17P_PARTIAL_ARM_CAPTURE next=%lu/%lu\n",
                               (unsigned long)(submission + 2),
                               (unsigned long)submission_count);
                        if (console != NULL)
                            fprintf(console,
                                    "G17P_PARTIAL_ARM_CAPTURE next=%lu/%lu\n",
                                    (unsigned long)(submission + 2),
                                    (unsigned long)submission_count);
                        fflush(stdout);
                        if (console != NULL)
                            fflush(console);
                    }
                    continue;
                }

                BOOL submission_exact = YES;
                for (NSUInteger checked_set = 0;
                     checked_set < target_set_count; ++checked_set) {
                    if (separate_submission_targets && checked_set > submission)
                        continue;
                    NSUInteger exact_pixels[attachment_count] = { 0 };
                    NSUInteger changed_bytes[attachment_count] = { 0 };
                    float accumulated_max[attachment_count] = { 0 };
                    for (NSUInteger attachment = 0;
                         attachment < attachment_count; ++attachment) {
                    const uint8_t *bytes =
                        [output_sets[checked_set][attachment] contents];
                    for (NSUInteger y = 0; y < height; ++y) {
                        for (NSUInteger x = 0; x < width; ++x) {
                            const uint8_t expected[4] = {
                                component_value(x, y, attachment, 2),
                                component_value(x, y, attachment, 1),
                                component_value(x, y, attachment, 0),
                                255,
                            };
                            const uint8_t *pixel =
                                bytes + y * bytes_per_row + x * 4;
                            if (memcmp(pixel, expected, sizeof(expected)) == 0)
                                exact_pixels[attachment]++;
                            for (NSUInteger component = 0; component < 4;
                                 ++component) {
                                if (pixel[component] != 0)
                                    changed_bytes[attachment]++;
                            }
                        }
                    }
                    if (accumulate) {
                        const float *values = (const float *)bytes;
                        for (NSUInteger pixel = 0; pixel < pixel_count;
                             ++pixel) {
                            if (isfinite(values[pixel]) &&
                                values[pixel] > accumulated_max[attachment])
                                accumulated_max[attachment] = values[pixel];
                        }
                        printf("G17P_PARTIAL_ACCUM submission=%lu set=%lu "
                               "index=%lu max=%.9g\n",
                               (unsigned long)(submission + 1),
                               (unsigned long)checked_set,
                               (unsigned long)attachment,
                               accumulated_max[attachment]);
                    }
                    printf("G17P_PARTIAL_TARGET submission=%lu set=%lu "
                           "index=%lu exact_pixels=%lu/%lu changed_bytes=%lu "
                           "first=%02x%02x%02x%02x\n",
                           (unsigned long)(submission + 1),
                           (unsigned long)checked_set,
                           (unsigned long)attachment,
                           (unsigned long)exact_pixels[attachment],
                           (unsigned long)pixel_count,
                           (unsigned long)changed_bytes[attachment], bytes[0],
                           bytes[1], bytes[2], bytes[3]);
                    }
                    for (NSUInteger i = 0; i < attachment_count; ++i) {
                    if (accumulate && constant_pressure)
                        submission_exact &= accumulated_max[i] ==
                            (float)(i + 1) * (float)triangle_count / 8.0f;
                    else if (accumulate)
                        submission_exact &= accumulated_max[i] >
                                (float)(i + 1) *
                                ((encode_all_in_one ||
                                  (enqueue_all && !separate_queue_targets &&
                                   !separate_submission_targets)) ?
                                    submission_count : 1) *
                                0.75f &&
                            accumulated_max[i] < (float)(i + 1) *
                                ((encode_all_in_one ||
                                  (enqueue_all && !separate_queue_targets &&
                                   !separate_submission_targets)) ?
                                    submission_count : 1) *
                                1.25f;
                    else if (concentrated || overflow || indirect)
                        submission_exact &= changed_bytes[i] != 0;
                    else
                        submission_exact &= exact_pixels[i] == pixel_count;
                    }
                }
                last_status = MTLCommandBufferStatusCompleted;
                last_error = nil;
                for (id<MTLCommandBuffer> submitted in submitted_commands) {
                    if ([submitted status] != MTLCommandBufferStatusCompleted) {
                        last_status = [submitted status];
                        last_error = [submitted error];
                        submission_exact = NO;
                    }
                }
                if (separate_submission_targets)
                    completed_submissions = submission + 1;
                else
                    completed_submissions += encode_all_in_one ?
                        submission_count : 1;
                exact &= submission_exact;
                printf("G17P_PARTIAL_SUBMISSION_DONE submission=%lu/%lu "
                       "status=%ld error=%s exact=%d\n",
                       (unsigned long)(submission + 1),
                       (unsigned long)submission_count, (long)last_status,
                       error_string(last_error), submission_exact);
                if (separate_submission_targets &&
                    !validate_independent_accumulation(output_sets,
                        completed_submissions, console,
                        constant_pressure ? (float)triangle_count / 8.0f : 1.0f,
                        constant_pressure ? 2 : 0))
                    return 12;
                if (capture_after == submission + 1) {
                    printf("G17P_PARTIAL_ARM_CAPTURE next=%lu/%lu\n",
                           (unsigned long)(submission + 2),
                           (unsigned long)submission_count);
                    if (console != NULL)
                        fprintf(console,
                                "G17P_PARTIAL_ARM_CAPTURE next=%lu/%lu\n",
                                (unsigned long)(submission + 2),
                                (unsigned long)submission_count);
                    fflush(stdout);
                    if (console != NULL)
                        fflush(console);
                }
            }
            if (!exact)
                break;
        }
        printf("G17P_PARTIAL_DONE status=%ld error=%s exact=%d "
               "submissions=%lu/%lu\n",
               (long)last_status, error_string(last_error), exact,
               (unsigned long)completed_submissions,
               (unsigned long)submission_count);
        if (console != NULL)
            fprintf(console,
                    "G17P_PARTIAL_DONE status=%ld exact=%d submissions=%lu/%lu\n",
                    (long)last_status, exact,
                    (unsigned long)completed_submissions,
                    (unsigned long)submission_count);
        return exact ? 0 : 9;
    }
}
