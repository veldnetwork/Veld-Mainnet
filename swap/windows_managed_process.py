"""Bounded Windows child lifecycle for the bundled operator runtime.

A job controls lifetime and resources, not custody-key isolation. The caller
must independently pin the executable and provide a constrained signing policy.
"""
import ctypes
from ctypes import wintypes as w
import os
import subprocess
import threading
import time


def run_managed(argv, input_raw, *, timeout, stdout_max, stderr_max, env=None):
    if os.name != "nt":
        raise RuntimeError("managed Windows processes require Windows")
    import _winapi
    import msvcrt
    if (not argv or not os.path.isabs(argv[0]) or not argv[0].lower().endswith(".exe") or
            argv[0].startswith(("\\\\", "//"))):
        raise RuntimeError("managed worker requires an absolute local executable path")
    command = subprocess.list2cmdline(argv)
    if len(command) >= 32767:
        raise RuntimeError("managed worker command is oversized")
    environment = dict(os.environ if env is None else env)
    if any(type(k) is not str or not k or "=" in k or "\0" in k or
           type(v) is not str or "\0" in v for k, v in environment.items()):
        raise RuntimeError("managed worker environment is malformed")
    if sum(len(k) + len(v) + 2 for k, v in environment.items()) >= 32767:
        raise RuntimeError("managed worker environment is oversized")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.c_void_p
    size = ctypes.c_size_t

    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
            ("flags", w.DWORD), ("minimum_working_set", size), ("maximum_working_set", size),
            ("active_process_limit", w.DWORD), ("affinity", size), ("priority", w.DWORD), ("scheduling", w.DWORD)]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", IoCounters), ("process_memory", size),
            ("job_memory", size), ("peak_process_memory", size), ("peak_job_memory", size)]

    def api(name, result, *args):
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, args
        return function

    create_job = api("CreateJobObjectW", w.HANDLE, ptr, w.LPCWSTR)
    set_job = api("SetInformationJobObject", w.BOOL, w.HANDLE, ctypes.c_int, ptr, w.DWORD)
    assign = api("AssignProcessToJobObject", w.BOOL, w.HANDLE, w.HANDLE)
    terminate = api("TerminateJobObject", w.BOOL, w.HANDLE, w.UINT)
    resume = api("ResumeThread", w.DWORD, w.HANDLE)
    close = api("CloseHandle", w.BOOL, w.HANDLE)
    job = create_job(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    handles, fds, threads, failures = [], [], [], []
    process = thread = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    guard = threading.Lock()
    deadline = time.monotonic() + timeout

    def fail(error):
        with guard:
            if not failures:
                failures.append(error)
        terminate(job, 1)

    def reader(fd, label, maximum):
        try:
            target = buffers[label]
            while True:
                chunk = os.read(fd, min(65536, maximum + 1 - len(target)))
                if not chunk:
                    break
                target.extend(chunk)
                if len(target) > maximum:
                    fail(RuntimeError("managed worker output exceeds safety limit"))
                    break
        except OSError as exc:
            fail(exc)
        finally:
            os.close(fd)

    def writer(fd):
        try:
            offset = 0
            while offset < len(input_raw):
                offset += os.write(fd, input_raw[offset:offset + 65536])
        except BrokenPipeError:
            pass
        except OSError as exc:
            if exc.errno != 22:
                fail(exc)
        finally:
            os.close(fd)

    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000 | 0x8 | 0x200
        limits.basic.active_process_limit = 16
        limits.job_memory = 512 * 1024 * 1024
        if not set_job(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        stdin_read, stdin_write = _winapi.CreatePipe(None, 0)
        handles += [stdin_read, stdin_write]
        stdout_read, stdout_write = _winapi.CreatePipe(None, 0)
        handles += [stdout_read, stdout_write]
        stderr_read, stderr_write = _winapi.CreatePipe(None, 0)
        handles += [stderr_read, stderr_write]
        inherited = [stdin_read, stdout_write, stderr_write]
        for handle in inherited:
            os.set_handle_inheritable(handle, True)
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESTDHANDLES | subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        startup.hStdInput, startup.hStdOutput, startup.hStdError = inherited
        startup.lpAttributeList = {"handle_list": inherited}
        process, thread, pid, tid = _winapi.CreateProcess(argv[0], command, None, None,
            True, 0x4 | 0x08000000, environment, os.path.dirname(os.path.abspath(argv[0])), startup)
        if not assign(job, process):
            raise ctypes.WinError(ctypes.get_last_error())
        for handle in inherited:
            _winapi.CloseHandle(handle)
            handles.remove(handle)
        for handle, mode in ((stdin_write, os.O_WRONLY), (stdout_read, os.O_RDONLY), (stderr_read, os.O_RDONLY)):
            fd = msvcrt.open_osfhandle(handle, mode | os.O_BINARY)
            handles.remove(handle)
            fds.append(fd)
        work = [(writer, (fds[0],)), (reader, (fds[1], "stdout", stdout_max)),
                (reader, (fds[2], "stderr", stderr_max))]
        for target, args in work:
            worker = threading.Thread(target=target, args=args, daemon=True)
            fd = fds.pop(0)
            try:
                worker.start()
            except BaseException:
                os.close(fd)
                raise
            threads.append(worker)
        if resume(thread) == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        _winapi.CloseHandle(thread)
        thread = None
        remaining = max(0, int((deadline - time.monotonic()) * 1000))
        waited = _winapi.WaitForSingleObject(process, remaining)
        if waited != _winapi.WAIT_OBJECT_0:
            raise subprocess.TimeoutExpired(argv, timeout)
        returncode = _winapi.GetExitCodeProcess(process)
        # The primary process cannot leave a descendant holding pipes or keys.
        terminate(job, 1)
        for worker in threads:
            worker.join(max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in threads):
            raise subprocess.TimeoutExpired(argv, timeout)
        if failures:
            raise failures[0]
        return subprocess.CompletedProcess(argv, returncode,
            stdout=bytes(buffers["stdout"]), stderr=bytes(buffers["stderr"]))
    finally:
        terminate(job, 1)
        if process is not None:
            # An assignment failure leaves the initial thread suspended outside
            # the job. Explicitly terminate it before dropping the process handle.
            try:
                _winapi.TerminateProcess(process, 1)
                _winapi.WaitForSingleObject(process, 5000)
            except OSError:
                pass
        for worker in threads:
            worker.join(5)
        for fd in fds:
            os.close(fd)
        for handle in handles:
            _winapi.CloseHandle(handle)
        if thread is not None:
            _winapi.CloseHandle(thread)
        if process is not None:
            _winapi.CloseHandle(process)
        close(job)
