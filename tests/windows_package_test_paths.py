"""Explicit Windows temporary-path cases for signed package qualification."""

import ctypes
from ctypes import wintypes
from pathlib import Path


TEMP_PATH_CASES = ("inherited", "long", "short")


def configure_temp_path(env, root, mode):
    if mode not in TEMP_PATH_CASES:
        raise ValueError("Unknown temporary-path case: " + mode)
    inherited = {name: env.get(name) for name in ("TEMP", "TMP")}
    if mode != "inherited":
        directory = Path(root) / "Temporary files with spaces é"
        directory.mkdir()
        path = str(directory)
        if mode == "short":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
            kernel.GetShortPathNameW.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            length = kernel.GetShortPathNameW(path, buffer, len(buffer))
            if not 0 < length < len(buffer):
                raise ctypes.WinError(ctypes.get_last_error())
            path = buffer.value
            if path.casefold() == str(directory).casefold() or "~" not in path:
                raise RuntimeError("This volume cannot exercise real Windows short paths")
            if Path(path).resolve() != directory.resolve():
                raise RuntimeError("Short path resolved to a different directory")
        env.update(TEMP=path, TMP=path)
    return {
        "mode": mode,
        "inherited": inherited,
        "effective": {name: env.get(name) for name in ("TEMP", "TMP")},
        "overridden": mode != "inherited",
    }
