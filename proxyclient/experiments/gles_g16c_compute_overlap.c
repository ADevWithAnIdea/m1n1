/* SPDX-License-Identifier: MIT */
/* Own bounded arithmetic workload for timestamp-based compute overlap tests. */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl31.h>
#include <stdint.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#ifndef M4MAX_PRIVATE_WORDS
#define M4MAX_PRIVATE_WORDS 64
#endif
#define M4MAX_STRING_INNER(x) #x
#define M4MAX_STRING(x) M4MAX_STRING_INNER(x)

int main(int argc, char **argv)
{
    PFNEGLQUERYDEVICESEXTPROC devices = (void *)eglGetProcAddress("eglQueryDevicesEXT");
    PFNEGLGETPLATFORMDISPLAYEXTPROC platform = (void *)eglGetProcAddress("eglGetPlatformDisplayEXT");
    EGLDeviceEXT candidates[16];
    EGLint count = 0;
    if (!devices || !platform || !devices(16, candidates, &count) || !count) return 2;
    EGLDisplay display = platform(EGL_PLATFORM_DEVICE_EXT,candidates[0],NULL);
    EGLint major,minor;
    if (!eglInitialize(display,&major,&minor) || !eglBindAPI(EGL_OPENGL_ES_API)) return 2;
    const EGLint attributes[] = {EGL_SURFACE_TYPE,EGL_PBUFFER_BIT,EGL_RENDERABLE_TYPE,EGL_OPENGL_ES3_BIT_KHR,EGL_NONE};
    EGLConfig config;
    EGLint configs;
    if (!eglChooseConfig(display,attributes,&config,1,&configs) || !configs) return 2;
    const EGLint surface_attributes[] = {EGL_WIDTH,1,EGL_HEIGHT,1,EGL_NONE};
    EGLSurface surface = eglCreatePbufferSurface(display,config,surface_attributes);
    const EGLint context_attributes[] = {EGL_CONTEXT_MAJOR_VERSION_KHR,3,EGL_CONTEXT_MINOR_VERSION_KHR,1,EGL_NONE};
    EGLContext context = eglCreateContext(display,config,EGL_NO_CONTEXT,context_attributes);
    if (context==EGL_NO_CONTEXT || !eglMakeCurrent(display,surface,surface,context)) return 2;
    const char *source = "#version 310 es\nlayout(local_size_x=16) in;\n"
        "layout(std430,binding=0) buffer Output { uint words[]; };\n"
        "uniform highp uint iterations;\n"
        "uint rotl(uint v,uint s){return (v<<s)|(v>>(32u-s));}\n"
        "void main(){uint i=gl_GlobalInvocationID.x;uint value=0x5a110000u^i;"
        "for(uint j=0u;j<iterations;j++) value=rotl(value,7u)+0x9e3779b9u+j;"
        "words[i]=value;}\n";
    GLuint shader = glCreateShader(GL_COMPUTE_SHADER);
    glShaderSource(shader,1,&source,NULL);
    glCompileShader(shader);
    GLint success;
    glGetShaderiv(shader,GL_COMPILE_STATUS,&success);
    if (!success) { char log[4096]; glGetShaderInfoLog(shader,sizeof(log),NULL,log); fputs(log,stderr); return 3; }
    GLuint program = glCreateProgram();
    glAttachShader(program,shader);
    glLinkProgram(program);
    glGetProgramiv(program,GL_LINK_STATUS,&success);
    if (!success) { char log[4096]; glGetProgramInfoLog(program,sizeof(log),NULL,log); fputs(log,stderr); return 3; }
    GLuint buffer;
    uint32_t seed[32];
    memset(seed,0xa5,sizeof(seed));
    glGenBuffers(1,&buffer);
    glBindBuffer(GL_SHADER_STORAGE_BUFFER,buffer);
    glBufferData(GL_SHADER_STORAGE_BUFFER,sizeof(seed),seed,GL_DYNAMIC_COPY);
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER,0,buffer);
    glUseProgram(program);
    GLint selector_location=glGetUniformLocation(program,"iterations");
    if(selector_location<0) return 3;
    glUniform1ui(selector_location,argc>1?(unsigned)strtoul(argv[1],NULL,0):1000000);
    printf("READY: %s, Mesa bounded arithmetic hash16\n",glGetString(GL_RENDERER));
    fflush(stdout);
    glDispatchCompute(1,1,1);
    glMemoryBarrier(GL_BUFFER_UPDATE_BARRIER_BIT|GL_SHADER_STORAGE_BARRIER_BIT);
    glFinish();
    return 0; /* Offline first-submit recorder exits before GPU execution. */
}
