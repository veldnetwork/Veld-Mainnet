#!/usr/bin/env python3
"""Format or verify maintained Veld C and C++ source."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys


GENERATED = {
    PurePosixPath("include/crypto/mldsa65_nist_kat.h"),
    PurePosixPath("include/crypto/vendored.h"),
    PurePosixPath("include/crypto/vendored_pin.h"),
    PurePosixPath("include/crypto/vendored_pin_expected.h"),
    PurePosixPath("include/crypto/vendored_pin_history.h"),
    PurePosixPath("include/network/dilithium_wasm_js.h"),
}


def find_clang_format() -> str:
    candidates = (
        shutil.which("clang-format"),
        r"C:\msys64\clang64\bin\clang-format.exe",
        r"C:\Program Files\LLVM\bin\clang-format.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise FileNotFoundError("clang-format was not found")


def maintained_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "src/*.cpp",
            "include/**/*.h",
            "tests/*.cpp",
            "tests/*.h",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[Path] = []
    for line in result.stdout.splitlines():
        relative = PurePosixPath(line)
        if relative in GENERATED or relative.name.endswith("_js.h"):
            continue
        paths.append(root / relative)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()

    root = args.root.resolve()
    clang_format = find_clang_format()
    paths = maintained_paths(root)
    if args.write:
        subprocess.run([clang_format, "-i", *map(str, paths)], check=True)
        print(f"PASS format-maintained-source mode=write files={len(paths)}")
        return 0

    failed: list[str] = []
    for path in paths:
        formatted = subprocess.run(
            [clang_format, str(path)], check=True, capture_output=True
        ).stdout
        if formatted != path.read_bytes():
            failed.append(path.relative_to(root).as_posix())
    if failed:
        print("Maintained source is not formatted:", file=sys.stderr)
        for path in failed:
            print(f"  {path}", file=sys.stderr)
        return 1
    print(f"PASS format-maintained-source mode=check files={len(paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
