/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef G17G_BRIDGE_H
#define G17G_BRIDGE_H
#include <stddef.h>
#include <stdint.h>

/* Process-local C dispatch beneath a libc/Mesa drm-shim interposer.
 * File identities are monotonically allocated open-file descriptions: dup()
 * aliases retain an identity, and only the last close calls close_file().
 * Return values use the DRM driver's zero/negative-errno convention. A libc
 * ioctl interposer must translate a negative return to -1 and set errno.
 */
int g17g_drm_init(int backing_fd);
int64_t g17g_drm_open_file(void);
int g17g_drm_close_file(uint64_t file);
int g17g_drm_ioctl(uint64_t file, unsigned long request, void *arg);
int64_t g17g_drm_mmap_offset(uint64_t file, uint64_t offset, size_t size);

/* Embedding support: caller holds the GIL and passes a G17GIoctlShim instance.
 * Returns EBUSY if a backend was already selected. Neither entry initializes
 * nor resets hardware. The usercopy module reports bad pointers as EFAULT.
 */
int g17g_drm_attach(void *python_backend);
void *g17g_drm_usercopy_module(void);
#endif
