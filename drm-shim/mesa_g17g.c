/* SPDX-License-Identifier: GPL-2.0-only
 * Linux/Mesa device discovery and libc entrypoints for the G17G dispatcher.
 * Build with mesa.patch against the pinned Mesa revision in prepare_mesa.py.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include "drm_shim.h"
#include "g17g_bridge.h"

bool drm_shim_driver_prefers_new_render_node = true;
static mtx_t bridge_lock;
static bool bridge_ready;

static int
file_open(struct shim_fd *file)
{
   mtx_lock(&bridge_lock);
   int ret = bridge_ready ? 0 : g17g_drm_init(shim_device.mem_fd);
   if (!ret)
      bridge_ready = true;
   mtx_unlock(&bridge_lock);
   if (ret)
      return ret;
   int64_t identity = g17g_drm_open_file();
   if (identity < 0)
      return (int)identity;
   file->driver_file = (uint64_t)identity;
   return 0;
}

static void
file_close(struct shim_fd *file)
{
   int ret = g17g_drm_close_file(file->driver_file);
   if (ret)
      fprintf(stderr, "G17G final file release: %d\n", ret);
}

static int
file_ioctl(int fd, unsigned long request, void *arg)
{
   struct shim_fd *file = drm_shim_fd_lookup(fd);
   return file ? g17g_drm_ioctl(file->driver_file, request, arg) : -EBADF;
}

static void *
file_mmap(struct shim_fd *file, void *addr, size_t length, int prot,
          int flags, off64_t offset)
{
   int64_t backing = g17g_drm_mmap_offset(file->driver_file, offset, length);
   if (backing < 0) {
      errno = (int)-backing;
      return MAP_FAILED;
   }
   return mmap(addr, length, prot, flags, shim_device.mem_fd, backing);
}

void
drm_shim_driver_init(void)
{
   mtx_init(&bridge_lock, mtx_plain);
   drm_shim_platform_device_setup("asahi", "/soc/gpu", "apple,agx-t8142");
   shim_device.version_major = 1;
   shim_device.driver_file_open = file_open;
   shim_device.driver_file_close = file_close;
   shim_device.driver_ioctl = file_ioctl;
   shim_device.driver_mmap = file_mmap;
}
