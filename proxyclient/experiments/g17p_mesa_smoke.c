/* SPDX-License-Identifier: MIT */
/* A no-argument Mesa/GLES-to-DRM transport witness for G17P. */

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <drm-uapi/asahi_drm.h>
#include <drm-uapi/drm_fourcc.h>
#include <fcntl.h>
#include <gbm.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef EGL_PLATFORM_GBM_KHR
#define EGL_PLATFORM_GBM_KHR 0x31D7
#endif

enum {
    WIDTH = 64,
    HEIGHT = 64,
};

static void require_egl(EGLBoolean result, const char *operation)
{
    if (!result) {
        fprintf(stderr, "%s failed: EGL error %#x\n", operation, eglGetError());
        exit(1);
    }
}

static void require_gl(const char *operation)
{
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        fprintf(stderr, "%s failed: GL error %#x\n", operation, error);
        exit(1);
    }
}

static GLuint compile_shader(GLenum type, const char *source)
{
    GLuint shader = glCreateShader(type);
    glShaderSource(shader, 1, &source, NULL);
    glCompileShader(shader);

    GLint compiled = 0;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        char log[4096];
        glGetShaderInfoLog(shader, sizeof(log), NULL, log);
        fprintf(stderr, "shader compilation failed: %s\n", log);
        exit(1);
    }
    return shader;
}

static GLuint build_program(void)
{
    static const char vertex_source[] = "attribute vec2 position;\n"
                                        "void main() { gl_Position = vec4(position, 0.0, 1.0); }\n";
    static const char fragment_source[] =
        "precision mediump float;\n"
        "void main() { gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0); }\n";

    GLuint vertex = compile_shader(GL_VERTEX_SHADER, vertex_source);
    GLuint fragment = compile_shader(GL_FRAGMENT_SHADER, fragment_source);
    GLuint program = glCreateProgram();
    glAttachShader(program, vertex);
    glAttachShader(program, fragment);
    glBindAttribLocation(program, 0, "position");
    glLinkProgram(program);
    glDeleteShader(vertex);
    glDeleteShader(fragment);

    GLint linked = 0;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (!linked) {
        char log[4096];
        glGetProgramInfoLog(program, sizeof(log), NULL, log);
        fprintf(stderr, "program link failed: %s\n", log);
        exit(1);
    }
    return program;
}

int main(void)
{
    static const EGLint config_attributes[] = {
        EGL_SURFACE_TYPE,
        EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE,
        EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE,
        8,
        EGL_GREEN_SIZE,
        8,
        EGL_BLUE_SIZE,
        8,
        EGL_ALPHA_SIZE,
        8,
        EGL_NONE,
    };
    static const EGLint context_attributes[] = {
        EGL_CONTEXT_CLIENT_VERSION,
        2,
        EGL_NONE,
    };
    /* One oversized triangle covers every sample in the viewport. */
    static const GLfloat vertices[] = {
        -1.0f, -1.0f, 3.0f, -1.0f, -1.0f, 3.0f,
    };

    int drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open render node");
        return 1;
    }
    struct gbm_device *gbm = gbm_create_device(drm_fd);
    if (!gbm) {
        fprintf(stderr, "gbm_create_device failed\n");
        return 1;
    }
    static const uint64_t modifiers[] = {DRM_FORMAT_MOD_APPLE_GPU_TILED};
    struct gbm_bo *bo = gbm_bo_create_with_modifiers2(
        gbm, WIDTH, HEIGHT, GBM_FORMAT_ARGB8888,
        modifiers, 1, GBM_BO_USE_RENDERING);
    if (!bo) {
        fprintf(stderr, "tiled render-target allocation failed\n");
        return 1;
    }
    if (gbm_bo_get_modifier(bo) != DRM_FORMAT_MOD_APPLE_GPU_TILED) {
        fprintf(stderr, "GBM did not allocate an Apple-tiled render target\n");
        return 1;
    }

    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    if (!get_platform_display) {
        fprintf(stderr, "EGL_EXT_platform_base is unavailable\n");
        return 1;
    }
    EGLDisplay display = get_platform_display(EGL_PLATFORM_GBM_KHR, gbm, NULL);
    require_egl(display != EGL_NO_DISPLAY, "eglGetPlatformDisplayEXT");
    require_egl(eglInitialize(display, NULL, NULL), "eglInitialize");
    require_egl(eglBindAPI(EGL_OPENGL_ES_API), "eglBindAPI");
    const char *extensions = eglQueryString(display, EGL_EXTENSIONS);
    if (!extensions || !strstr(extensions, "EGL_KHR_surfaceless_context")) {
        fprintf(stderr, "EGL_KHR_surfaceless_context is unavailable\n");
        return 1;
    }

    EGLConfig config;
    EGLint count = 0;
    require_egl(eglChooseConfig(display, config_attributes, &config, 1, &count), "eglChooseConfig");
    if (count != 1) {
        fprintf(stderr, "no matching EGL config\n");
        return 1;
    }

    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    require_egl(context != EGL_NO_CONTEXT, "eglCreateContext");
    require_egl(
        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, context),
        "eglMakeCurrent surfaceless");

    PFNEGLCREATEIMAGEKHRPROC create_image =
        (PFNEGLCREATEIMAGEKHRPROC)eglGetProcAddress("eglCreateImageKHR");
    PFNEGLDESTROYIMAGEKHRPROC destroy_image =
        (PFNEGLDESTROYIMAGEKHRPROC)eglGetProcAddress("eglDestroyImageKHR");
    PFNGLEGLIMAGETARGETTEXTURE2DOESPROC image_target_texture =
        (PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)
            eglGetProcAddress("glEGLImageTargetTexture2DOES");
    if (!create_image || !destroy_image || !image_target_texture) {
        fprintf(stderr, "EGL/GL image import entrypoints are unavailable\n");
        return 1;
    }
    static const EGLint image_attributes[] = {EGL_IMAGE_PRESERVED_KHR, EGL_TRUE, EGL_NONE};
    EGLImageKHR image = create_image(
        display, EGL_NO_CONTEXT, EGL_NATIVE_PIXMAP_KHR,
        (EGLClientBuffer)bo, image_attributes);
    require_egl(image != EGL_NO_IMAGE_KHR, "eglCreateImageKHR");

    GLuint target_texture = 0;
    glGenTextures(1, &target_texture);
    glBindTexture(GL_TEXTURE_2D, target_texture);
    image_target_texture(GL_TEXTURE_2D, image);
    require_gl("tiled target import");

    GLuint framebuffer = 0;
    glGenFramebuffers(1, &framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
        target_texture, 0);
    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        fprintf(stderr, "tiled target framebuffer is incomplete\n");
        return 1;
    }

    printf("GL_RENDERER=%s\n", glGetString(GL_RENDERER));
    GLuint program = build_program();
    glViewport(0, 0, WIDTH, HEIGHT);
    glClearColor(0.0f, 0.0f, 1.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glUseProgram(program);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, vertices);
    glEnableVertexAttribArray(0);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glFinish();
    require_gl("draw");

    struct drm_asahi_gem_mmap_offset map = {
        .handle = gbm_bo_get_handle(bo).u32,
    };
    if (ioctl(drm_fd, DRM_IOCTL_ASAHI_GEM_MMAP_OFFSET, &map) != 0) {
        perror("DRM_IOCTL_ASAHI_GEM_MMAP_OFFSET");
        return 1;
    }
    const size_t raw_size = (size_t)WIDTH * HEIGHT * 4;
    const uint8_t *pixels = mmap(
        NULL, raw_size, PROT_READ, MAP_SHARED, drm_fd, map.offset);
    if (pixels == MAP_FAILED) {
        perror("mmap tiled target");
        return 1;
    }

    size_t source_incorrect = 0;
    size_t zero_words = 0;
    size_t accumulated_words = 0;
    size_t clear_nan_words = 0;
    size_t marker_words = 0;
    size_t expected_bgra_red_words = 0;
    size_t unexpected_rgba_red_words = 0;
    const size_t first_result = 0x3efc / sizeof(uint32_t);
    const size_t second_result = 0x3f00 / sizeof(uint32_t);
    size_t marker_base = WIDTH * HEIGHT;
    uint32_t marker_value = 0;
    uint64_t marker_rows[4] = {0};
    bool marker_invalid = false;
    for (size_t index = 0; index < WIDTH * HEIGHT; ++index) {
        const uint8_t *rgba = &pixels[index * 4];
        uint32_t word;
        memcpy(&word, rgba, sizeof(word));
        float value;
        memcpy(&value, &word, sizeof(value));
        const bool accumulated = value >= 0.98f && value <= 1.02f;
        const bool clear_nan =
            (word & 0x7f800000u) == 0x7f800000u &&
            (word & 0x007fffffu) != 0;
        zero_words += word == 0x00000000;
        accumulated_words += accumulated;
        clear_nan_words += clear_nan;
        expected_bgra_red_words += word == 0xffff0000;
        unexpected_rgba_red_words += word == 0xff0000ff;
        if (index == first_result || index == second_result) {
            if (!accumulated && !clear_nan)
                ++source_incorrect;
        } else if (word != 0) {
            if (marker_base == WIDTH * HEIGHT) {
                marker_base = index;
                marker_value = word;
            }

            const size_t relative = index - marker_base;
            const size_t row = relative / (0x200 / sizeof(uint32_t));
            const size_t column = relative % (0x200 / sizeof(uint32_t));
            if (row >= 4 || column >= (0x100 / sizeof(uint32_t)) ||
                word != marker_value) {
                marker_invalid = true;
            } else {
                marker_rows[row] |= UINT64_C(1) << column;
                ++marker_words;
            }
        }
    }
    if (marker_base != WIDTH * HEIGHT &&
        (marker_invalid || marker_value == 0 || marker_value > 48217 ||
         marker_rows[0] == 0 || marker_rows[0] != marker_rows[1] ||
         marker_rows[0] != marker_rows[2] ||
         marker_rows[0] != marker_rows[3])) {
        ++source_incorrect;
    }
    if (accumulated_words < 1)
        ++source_incorrect;
    printf("raw_first_64=");
    for (size_t index = 0; index < 64; ++index)
        printf("%02x", pixels[index]);
    printf("\nraw_word_counts zero=%zu accumulated=%zu clear_nan=%zu marker=%zu "
           "expected_bgra_red=%zu unexpected_rgba_red=%zu other=%zu\n",
           zero_words, accumulated_words, clear_nan_words, marker_words,
           expected_bgra_red_words, unexpected_rgba_red_words,
           (size_t)WIDTH * HEIGHT - zero_words - expected_bgra_red_words -
               unexpected_rgba_red_words - accumulated_words -
               clear_nan_words - marker_words);
    printf("source_partial_integration=%s layout=caller-gem-page "
           "incorrect_words=%zu/%d\n",
           source_incorrect ? "FAIL" : "PASS", source_incorrect,
           WIDTH * HEIGHT);

    munmap((void *)pixels, raw_size);
    glDeleteProgram(program);
    glDeleteFramebuffers(1, &framebuffer);
    glDeleteTextures(1, &target_texture);
    require_egl(destroy_image(display, image), "eglDestroyImageKHR");
    eglDestroyContext(display, context);
    eglTerminate(display);
    gbm_bo_destroy(bo);
    gbm_device_destroy(gbm);
    close(drm_fd);
    return source_incorrect ? 2 : 0;
}
