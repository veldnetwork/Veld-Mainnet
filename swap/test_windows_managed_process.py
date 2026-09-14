import ctypes
from ctypes import wintypes as w
import os
import subprocess
import sys
import time
import unittest

from rpc_url_policy import run_bounded_subprocess


@unittest.skipUnless(os.name == "nt", "actual Windows job-object checks")
class ManagedProcessTests(unittest.TestCase):
    def run_child(self, code, **kwargs):
        options = dict(timeout=5, stdout_max=4096, stderr_max=4096)
        options.update(kwargs)
        return run_bounded_subprocess([sys.executable, "-I", "-c", code], **options)

    def test_bounded_input_and_separate_streams(self):
        result = self.run_child("import sys; print(sys.stdin.read()); print('error',file=sys.stderr)", input_text="exact input")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "exact input")
        self.assertEqual(result.stderr.strip(), "error")

    def test_nonzero_return_code_preserved(self):
        self.assertEqual(self.run_child("raise SystemExit(27)").returncode, 27)

    def test_deadline_terminates_worker(self):
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_child("import time; time.sleep(30)", timeout=0.25)
        self.assertLess(time.monotonic() - start, 5)

    def test_stdout_flood_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, "output exceeds"):
            self.run_child("import os; os.write(1,b'x'*100000)")

    def test_stderr_flood_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, "output exceeds"):
            self.run_child("import os; os.write(2,b'x'*100000)")

    def test_simultaneous_large_input_and_output_do_not_deadlock(self):
        result = self.run_child("import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)",
            input_text="x" * 200000, stdout_max=200000)
        self.assertEqual(result.stdout, "x" * 200000)

    def test_invalid_utf8_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "UTF-8"):
            self.run_child("import os; os.write(1,b'\\xff')")

    def test_relative_executable_refused(self):
        with self.assertRaisesRegex(RuntimeError, "absolute local executable"):
            run_bounded_subprocess(["python.exe", "-V"], timeout=1, stdout_max=100, stderr_max=100)

    def test_child_is_already_in_a_job_when_code_starts(self):
        result = self.run_child("import ctypes; from ctypes import wintypes as w; k=ctypes.WinDLL('kernel32'); "
            "k.GetCurrentProcess.restype=w.HANDLE; k.IsProcessInJob.argtypes=[w.HANDLE,w.HANDLE,ctypes.POINTER(w.BOOL)]; "
            "answer=w.BOOL(); assert k.IsProcessInJob(k.GetCurrentProcess(),None,ctypes.byref(answer)); print(bool(answer.value))")
        self.assertEqual(result.stdout.strip(), "True")

    def test_descendant_is_terminated_when_primary_exits(self):
        result = self.run_child("import subprocess,sys; p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)']); print(p.pid,flush=True)")
        pid = int(result.stdout.strip())
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        kernel.OpenProcess.restype = w.HANDLE
        kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = kernel.OpenProcess(0x100000, False, pid)
        if handle:
            try:
                self.assertEqual(kernel.WaitForSingleObject(handle, 1000), 0)
            finally:
                kernel.CloseHandle(handle)

    def test_only_explicit_handles_are_inherited(self):
        import _winapi
        read, write = _winapi.CreatePipe(None, 0)
        try:
            os.set_handle_inheritable(write, True)
            result = self.run_child("import ctypes; from ctypes import wintypes as w; k=ctypes.WinDLL('kernel32'); "
                "k.GetHandleInformation.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]; flags=w.DWORD(); "
                f"print(bool(k.GetHandleInformation({write},ctypes.byref(flags))))")
            self.assertEqual(result.stdout.strip(), "False")
        finally:
            _winapi.CloseHandle(read)
            _winapi.CloseHandle(write)


if __name__ == "__main__":
    unittest.main()
