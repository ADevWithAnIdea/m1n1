/* SPDX-License-Identifier: GPL-2.0-only
 * A native C process must initialize the correct Python environment without
 * opening the GPU. This tests the initialization route the ctypes tests do
 * not exercise. No UAPI hardware submission or execution claim is made here.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "g17g_bridge.h"

int main(void)
{
    char path[] = "/tmp/g17g-native-init-XXXXXX";
    int backing = mkstemp(path);
    if (backing < 0)
        return 1;
    unlink(path);
    if (g17g_drm_init(backing) || g17g_drm_init(backing) != -EBUSY)
        return 2;
    int64_t first = g17g_drm_open_file();
    if (first <= 0 || g17g_drm_close_file(first))
        return 3;
    int64_t second = g17g_drm_open_file();
    if (second <= first || g17g_drm_close_file(second))
        return 4;
    close(backing);
    return 0;
}
