/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <Python.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#else
#include <sys/uio.h>
#endif
#include "g17g_bridge.h"

static PyObject *backend;
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

/* Use fault-reporting copies, including for nested UAPI arrays. A bad caller
 * pointer must fail an ioctl instead of terminating the Python interpreter.
 */
static int
copy_user(void *local, uintptr_t remote, size_t size, int write)
{
    if (!size)
        return 0;
    if (!remote || remote + size < remote || size > 64 * 1024 * 1024)
        return -EFAULT;
#ifdef __APPLE__
    kern_return_t ret;
    if (write) {
        ret = mach_vm_write(mach_task_self(), remote, (vm_offset_t)local,
                            (mach_msg_type_number_t)size);
    } else {
        mach_vm_size_t copied = 0;
        ret = mach_vm_read_overwrite(mach_task_self(), remote, size,
                                    (mach_vm_address_t)local, &copied);
        if (copied != size)
            return -EFAULT;
    }
    return ret == KERN_SUCCESS ? 0 : -EFAULT;
#else
    struct iovec local_iov = {local, size};
    struct iovec remote_iov = {(void *)remote, size};
    ssize_t ret = write
        ? process_vm_writev(getpid(), &local_iov, 1, &remote_iov, 1, 0)
        : process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return ret == (ssize_t)size ? 0 : -EFAULT;
#endif
}

static PyObject *
user_read(PyObject *self, PyObject *args)
{
    (void)self;
    unsigned long long pointer;
    Py_ssize_t size;
    if (!PyArg_ParseTuple(args, "Kn", &pointer, &size))
        return NULL;
    if (size < 0 || size > 64 * 1024 * 1024) {
        PyErr_SetString(PyExc_ValueError, "invalid usercopy length");
        return NULL;
    }
    PyObject *result = PyBytes_FromStringAndSize(NULL, size);
    if (!result)
        return NULL;
    if (copy_user(PyBytes_AS_STRING(result), pointer, size, 0)) {
        Py_DECREF(result);
        errno = EFAULT;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return result;
}

static PyObject *
user_write(PyObject *self, PyObject *args)
{
    (void)self;
    unsigned long long pointer;
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "Ky*", &pointer, &data))
        return NULL;
    int ret = copy_user(data.buf, pointer, data.len, 1);
    PyBuffer_Release(&data);
    if (ret) {
        errno = EFAULT;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    Py_RETURN_NONE;
}

static PyMethodDef memory_methods[] = {
    {"read", user_read, METH_VARARGS, "Fault-reporting user memory read."},
    {"write", user_write, METH_VARARGS, "Fault-reporting user memory write."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef memory_module = {
    PyModuleDef_HEAD_INIT, "_g17g_usercopy", NULL, -1, memory_methods,
    NULL, NULL, NULL, NULL,
};

void *
g17g_drm_usercopy_module(void)
{
    return PyModule_Create(&memory_module);
}

int
g17g_drm_attach(void *python_backend)
{
    if (backend)
        return -EBUSY;
    backend = Py_NewRef((PyObject *)python_backend);
    return 0;
}

int
g17g_drm_init(int backing_fd)
{
    pthread_mutex_lock(&init_lock);
    if (backend) {
        pthread_mutex_unlock(&init_lock);
        return -EBUSY;
    }
    int owns_python = !Py_IsInitialized();
    if (owns_python) {
        PyConfig config;
        PyConfig_InitPythonConfig(&config);
        config.parse_argv = 0;
        config.install_signal_handlers = 0;
        PyStatus status = PyStatus_Ok();
#ifdef G17G_PYTHON_EXECUTABLE
        /* Discover the same virtualenv used to build the embedding ABI. */
        status = PyConfig_SetBytesString(&config, &config.program_name,
                                         G17G_PYTHON_EXECUTABLE);
#endif
        if (!PyStatus_Exception(status))
            status = Py_InitializeFromConfig(&config);
        int failed = PyStatus_Exception(status);
        if (failed)
            fprintf(stderr, "G17G Python initialization: %s\n",
                    status.err_msg ? status.err_msg : "initialization failed");
        PyConfig_Clear(&config);
        if (failed) {
            pthread_mutex_unlock(&init_lock);
            return -EIO;
        }
    }
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *module = PyImport_ImportModule("m1n1.g17g_shim_entry");
    PyObject *klass = module ? PyObject_GetAttrString(module, "Shim") : NULL;
    PyObject *memory = klass ? g17g_drm_usercopy_module() : NULL;
    if (memory)
        backend = PyObject_CallFunction(klass, "iO", backing_fd, memory);
    Py_XDECREF(memory);
    Py_XDECREF(klass);
    Py_XDECREF(module);
    int ret = backend ? 0 : -EIO;
    if (PyErr_Occurred())
        PyErr_Print();
    PyGILState_Release(gil);
    if (owns_python)
        PyEval_SaveThread();
    pthread_mutex_unlock(&init_lock);
    return ret;
}

/* These helpers are only called while holding the GIL. */
static int64_t
result_long(PyObject *result)
{
    int64_t ret = -EIO;
    if (result) {
        ret = PyLong_AsLongLong(result);
        Py_DECREF(result);
    }
    if (PyErr_Occurred()) {
        ret = -EIO;
        PyObject *type, *value, *trace;
        PyErr_Fetch(&type, &value, &trace);
        PyErr_NormalizeException(&type, &value, &trace);
        if (value && PyObject_IsInstance(value, PyExc_OSError) == 1) {
            PyObject *code = PyObject_GetAttrString(value, "errno");
            if (code && PyLong_Check(code)) {
                long error = PyLong_AsLong(code);
                if (error > 0 && error < 4096)
                    ret = -error;
            }
            Py_XDECREF(code);
        }
        PyErr_Restore(type, value, trace);
        PyErr_Print();
        if (ret >= 0)
            ret = -EIO;
    }
    return ret;
}

int64_t
g17g_drm_open_file(void)
{
    if (!backend)
        return -ENODEV;
    PyGILState_STATE gil = PyGILState_Ensure();
    int64_t ret = result_long(PyObject_CallMethod(backend, "open_file", NULL));
    PyGILState_Release(gil);
    return ret;
}

int
g17g_drm_close_file(uint64_t file)
{
    if (!backend)
        return -ENODEV;
    PyGILState_STATE gil = PyGILState_Ensure();
    int64_t ret = result_long(PyObject_CallMethod(backend, "close_file", "K",
                                                (unsigned long long)file));
    PyGILState_Release(gil);
    return ret;
}

int64_t
g17g_drm_mmap_offset(uint64_t file, uint64_t offset, size_t size)
{
    if (!backend)
        return -ENODEV;
    PyGILState_STATE gil = PyGILState_Ensure();
    int64_t ret = result_long(PyObject_CallMethod(backend, "mmap_offset", "KKK",
        (unsigned long long)file, (unsigned long long)offset, (unsigned long long)size));
    PyGILState_Release(gil);
    return ret;
}

int
g17g_drm_ioctl(uint64_t file, unsigned long request, void *arg)
{
    if (!backend)
        return -ENODEV;
    if (((request >> 8) & 0xff) != 'd')
        return -ENOTTY;
    /* DRM payloads fit in the common 13 size bits on Linux and BSD/Darwin. */
    size_t size = (request >> 16) & 0x1fff;
    if (size > 4096)
        return -EINVAL;
    char buffer[4096];
    int ret = copy_user(buffer, (uintptr_t)arg, size, 0);
    if (ret)
        return ret;
    PyGILState_STATE gil = PyGILState_Ensure();
    PyObject *input = PyBytes_FromStringAndSize(buffer, size);
    PyObject *result = input ? PyObject_CallMethod(backend, "ioctl", "KIO",
        (unsigned long long)file, (unsigned int)(request & 0xff), input) : NULL;
    Py_XDECREF(input);
    PyObject *output;
    if (!result || !PyArg_ParseTuple(result, "iO", &ret, &output)) {
        if (PyErr_Occurred())
            PyErr_Print();
        ret = -EIO;
    } else if (!ret) {
        if (!PyBytes_Check(output) || PyBytes_GET_SIZE(output) != (Py_ssize_t)size)
            ret = -EIO;
        else if (request &
#ifdef __APPLE__
                 0x40000000ul
#else
                 0x80000000ul
#endif
                 )
            ret = copy_user(PyBytes_AS_STRING(output), (uintptr_t)arg, size, 1);
    }
    Py_XDECREF(result);
    PyGILState_Release(gil);
    return ret;
}
