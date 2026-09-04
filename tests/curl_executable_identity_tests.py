#!/usr/bin/env python3
"""Compile and exercise trusted system-curl executable identity."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "curl_executable_identity_tests.cpp"
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def compiler() -> str:
    candidates = [
        os.environ.get("CXX", ""),
        shutil.which("clang++") or "",
        shutil.which("g++") or "",
        r"C:\msys64\clang64\bin\clang++.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("no C++ compiler available for curl identity fixture")


def main() -> None:
    process = (ROOT / "include" / "compat" / "process.h").read_text("utf-8")
    node = (ROOT / "include" / "node" / "node.h").read_text("utf-8")
    resolver_start = process.index("inline std::string TrustedSystemCurlExecutable()")
    resolver_end = process.index(
        "\n#ifdef _WIN32\ninline std::string QuoteWindowsArg", resolver_start)
    resolver = process[resolver_start:resolver_end]

    check("GetWindowsDirectoryA" in resolver and
          "GetSystemDirectoryA" in resolver and
          "GetFinalPathNameByHandleA" in resolver,
          "Windows curl identity is not bound to the canonical system path")
    check("FILE_ATTRIBUTE_REPARSE_POINT" in resolver and
          "FILE_FLAG_OPEN_REPARSE_POINT" in resolver,
          "Windows curl identity does not reject reparse substitution")
    check('"/usr/bin/curl"' in resolver and '"/bin/curl"' in resolver and
          '"/usr/local/bin/curl"' in resolver and "::realpath" in resolver,
          "POSIX curl resolver lacks a fixed canonical system allowlist")
    check("status.st_uid != 0" in resolver and
          "status.st_size <= 0" in resolver and
          "S_IWGRP | S_IWOTH" in resolver and
          "::access(canonical.c_str(), X_OK)" in resolver,
          "POSIX curl resolver lacks root-owner/write/execute checks")
    check(
        all(
            token not in resolver
            for token in (
                "getenv(",
                "std::getenv(",
                "::getenv(",
                "GetEnvironmentVariable",
                "SearchPath",
            )
        ),
        "trusted curl resolver still depends on PATH/environment",
    )
    check(node.count("compat::TrustedSystemCurlExecutable()") == 2 and
          node.count("if (curl_executable.empty())") == 2,
          "both node curl sinks are not fail-closed on trusted resolution")
    oracle_start = node.index("void OracleSyncCheckImpl_()")
    oracle_resolve = node.index("compat::TrustedSystemCurlExecutable()",
                                oracle_start)
    oracle_refuse = node.index("if (curl_executable.empty())", oracle_resolve)
    oracle_launch = node.index("compat::RunProcess(", oracle_refuse)
    checkpoint_start = node.index("size_t LoadCheckpointsFromUrl()")
    checkpoint_resolve = node.index("compat::TrustedSystemCurlExecutable()",
                                    checkpoint_start)
    checkpoint_refuse = node.index("if (curl_executable.empty())",
                                   checkpoint_resolve)
    checkpoint_launch = node.index("compat::RunProcessToBoundedFile(",
                                   checkpoint_refuse)
    check(oracle_resolve < oracle_refuse < oracle_launch and
          checkpoint_resolve < checkpoint_refuse < checkpoint_launch,
          "a node curl sink can launch before trusted-resolution refusal")
    check('{curl_executable, "--disable", "-fsS"' in node and
          '{curl_executable, "--disable", "--fail", "--silent"' in node and
          '{"curl"' not in node,
          "node retains an unqualified curl child or lost config disabling")

    with tempfile.TemporaryDirectory(prefix="veld-f8-curl-identity-build-") as tmp:
        binary = Path(tmp) / (
            "curl-identity-tests.exe" if os.name == "nt" else
            "curl-identity-tests")
        command = [
            compiler(), "-std=c++20", "-O2", str(SOURCE), "-o", str(binary),
        ]
        command.insert(3, "-static")
        build = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, timeout=120)
        check(build.returncode == 0,
              f"curl identity fixture compile failed: {build.stderr}")
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True, capture_output=True, timeout=30)
        check(run.returncode == 0,
              f"curl identity fixture failed: stdout={run.stdout!r} "
              f"stderr={run.stderr!r}")
        check("PASS curl_executable_identity_tests" in run.stdout and
              "trusted=" in run.stdout,
              "curl identity fixture did not report trusted execution")
        print(run.stdout.strip())

        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            chroot = shutil.which("chroot")
            check(chroot is not None,
                  "root curl-absence fixture has no chroot executable")
            empty_root = Path(tmp) / "empty-root"
            empty_root.mkdir()
            jailed_binary = empty_root / "identity-tests"
            shutil.copy2(binary, jailed_binary)
            unavailable = subprocess.run(
                [chroot, str(empty_root), "/identity-tests",
                 "--expect-unavailable"],
                cwd=ROOT, text=True, capture_output=True, timeout=30)
            check(unavailable.returncode == 0 and
                  "trusted-system-curl-unavailable-fail-closed" in
                  unavailable.stdout,
                  f"curl-absence chroot fixture failed: "
                  f"stdout={unavailable.stdout!r} stderr={unavailable.stderr!r}")
            print(unavailable.stdout.strip())

    print(f"PASS curl_executable_identity_tests.py checks={checks}")


if __name__ == "__main__":
    main()
