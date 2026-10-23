#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <asahi_drm.h>
int ioctl(int fd, unsigned long request, ...) {
 va_list ap; va_start(ap, request); void *arg=va_arg(ap,void *); va_end(ap);
 static int (*real_ioctl)(int,unsigned long,...);
 if (!real_ioctl) *(void **)(&real_ioctl)=dlsym(RTLD_NEXT,"ioctl");
 int rc=real_ioctl(fd,request,arg); int saved=errno;
 if(request==DRM_IOCTL_ASAHI_VM_BIND) {
  const struct drm_asahi_vm_bind *b=arg;
  fprintf(stderr,"BIND_TRACE pid=%ld fd=%d rc=%d errno=%d vm=%u count=%u stride=%u pad=%u\n",(long)getpid(),fd,rc,saved,b->vm_id,b->num_binds,b->stride,b->pad);
  if(b->num_binds<1024 && b->stride>=sizeof(struct drm_asahi_gem_bind_op)) for(uint32_t i=0;i<b->num_binds;i++) {
   const struct drm_asahi_gem_bind_op *o=(void *)((uintptr_t)b->userptr+(uintptr_t)i*b->stride);
   fprintf(stderr,"BIND_TRACE op=%u flags=%#llx handle=%u offset=%#llx range=%#llx addr=%#llx\n",i,(unsigned long long)o->flags,o->handle,(unsigned long long)o->offset,(unsigned long long)o->range,(unsigned long long)o->addr);
  }
 }
 if(request==DRM_IOCTL_ASAHI_VM_CREATE && rc==0){const struct drm_asahi_vm_create *c=arg;fprintf(stderr,"BIND_TRACE vmcreate pid=%ld vm=%u kernel_start=%#llx kernel_end=%#llx\n",(long)getpid(),c->vm_id,(unsigned long long)c->kernel_start,(unsigned long long)c->kernel_end);}
 if(request==DRM_IOCTL_ASAHI_GEM_CREATE && rc==0){const struct drm_asahi_gem_create *c=arg;fprintf(stderr,"BIND_TRACE gemcreate pid=%ld handle=%u vm=%u flags=%#x size=%#llx\n",(long)getpid(),c->handle,c->vm_id,c->flags,(unsigned long long)c->size);}
 errno=saved;return rc;
}
