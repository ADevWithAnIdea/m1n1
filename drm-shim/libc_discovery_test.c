/* SPDX-License-Identifier: GPL-2.0-only
 * A native Linux process using real libc/libdrm entrypoints. No GPU required.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <xf86drm.h>

#define REQUIRE(test) do { if (!(test)) { \
   fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #test, errno); \
   return 1; \
} } while (0)

int main(void)
{
   int fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
   REQUIRE(fd >= 0);
   REQUIRE(fcntl(fd, F_GETFD) & FD_CLOEXEC);
   struct stat status;
   REQUIRE(fstat(fd, &status) == 0);
   REQUIRE(S_ISCHR(status.st_mode) && major(status.st_rdev) == 226);
   drmVersionPtr version = drmGetVersion(fd);
   REQUIRE(version && strcmp(version->name, "asahi") == 0);
   REQUIRE(version->version_major == 1);
   drmFreeVersion(version);
   drmDevicePtr device = NULL;
   REQUIRE(drmGetDevice2(fd, 0, &device) == 0);
   REQUIRE(device && device->bustype == DRM_BUS_PLATFORM);
   REQUIRE(device->available_nodes & (1 << DRM_NODE_RENDER));
   drmFreeDevice(&device);
   uint64_t capability;
   REQUIRE(drmGetCap(fd, DRM_CAP_SYNCOBJ, &capability) == 0 && capability == 1);
   REQUIRE(drmGetCap(fd, DRM_CAP_SYNCOBJ_TIMELINE, &capability) == 0 && capability == 1);
   REQUIRE(drmGetCap(fd, DRM_CAP_PRIME, &capability) == 0 && capability == 0);
   errno = 0;
   REQUIRE(ioctl(fd, DRM_IOCTL_GET_CAP, (void *)1) == -1 && errno == EFAULT);
   struct drm_version bad = {.name_len = 5, .name = (void *)1};
   REQUIRE(ioctl(fd, DRM_IOCTL_VERSION, &bad) == -1 && errno == EFAULT);
   struct drm_get_cap unknown = {0};
   REQUIRE(ioctl(fd, DRM_IOWR(0xfe, struct drm_get_cap), &unknown) == -1 && errno == ENOTTY);
   int duplicate = dup(fd);
   REQUIRE(duplicate >= 0);
   REQUIRE(close(fd) == 0);
   version = drmGetVersion(duplicate);
   REQUIRE(version && strcmp(version->name, "asahi") == 0);
   drmFreeVersion(version);
   REQUIRE(fcntl(duplicate, F_DUPFD_CLOEXEC, -1) == -1 && errno == EINVAL);
   REQUIRE(close(duplicate) == 0);
   puts("PASS libc/libdrm discovery, capabilities, errno and dup lifetime");
   return 0;
}
