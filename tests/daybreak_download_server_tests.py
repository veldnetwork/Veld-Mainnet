#!/usr/bin/env python3
"""Executable transfer-boundary and release-downloader regressions."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "daybreak_bounded_download_tests.cpp"
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
    raise RuntimeError("no C++20 compiler available")


class OneRequestServer:
    def __init__(self, responder):
        self.responder = responder
        self.requests = 0
        self.error: BaseException | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            self.listener.settimeout(5)
            conn, _ = self.listener.accept()
            self.requests += 1
            with conn:
                conn.settimeout(2)
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) <= 65536:
                    part = conn.recv(4096)
                    if not part:
                        break
                    request.extend(part)
                self.responder(conn, bytes(request))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except BaseException as exc:  # surfaced in __exit__
            self.error = exc
        finally:
            self.listener.close()

    def __exit__(self, exc_type, exc, tb):
        self.thread.join(timeout=6)
        check(not self.thread.is_alive(), "HTTP fixture thread did not finish")
        if self.error is not None:
            raise self.error


RESULT = re.compile(r"^status=(\d+) exit=(-?\d+) bytes=(\d+) exists=([01])$")


def fetch(client: Path, server: OneRequestServer, destination: Path,
          maximum: int, deadline_ms: int) -> tuple[int, int, int, int]:
    run = subprocess.run(
        [str(client), "--fetch", f"http://127.0.0.1:{server.port}/fixture",
         str(destination), str(maximum), str(deadline_ms)],
        cwd=ROOT, text=True, capture_output=True, timeout=10,
    )
    check(run.returncode == 0, f"fetch fixture failed: {run.stderr}")
    match = RESULT.fullmatch(run.stdout.strip())
    check(match is not None, f"malformed fetch result: {run.stdout!r}")
    return tuple(int(value) for value in match.groups())


def main() -> None:
    process = (ROOT / "include" / "compat" / "process.h").read_text("utf-8")
    node = (ROOT / "include" / "node" / "node.h").read_text("utf-8")
    public_snapshot = (ROOT / "include" / "node" / "public_snapshot_bootstrap.h").read_text("utf-8")
    checkpoints = (ROOT / "include" / "consensus" / "checkpoints.h").read_text("utf-8")
    updater = (ROOT / "pkg" / "veld-update.ps1").read_text("utf-8")
    tor_setup = (ROOT / "pkg" / "tor-setup.ps1").read_text("utf-8")
    mining_launcher = (ROOT / "pkg" / "Start Mining.bat").read_text("utf-8")
    validator_launcher = (ROOT / "pkg" / "Start Validator.bat").read_text("utf-8")
    check("RunProcessToBoundedFile" in process and "ByteLimitExceeded" in process,
          "parent transfer-boundary primitive missing")
    check("kMaxCheckpointDocumentBytes" in checkpoints and
          "json.size() > kMaxCheckpointDocumentBytes" in checkpoints,
          "checkpoint parser does not share transfer cap")
    check("std::string obj = json.substr" not in checkpoints and
          "const std::string_view obj" in checkpoints,
          "checkpoint parser retains a complete object copy")
    check("end - pos > max_length" in checkpoints,
          "checkpoint parser copies oversized fields before validation")
    check('"--max-filesize"' in node and '"--max-redirs", "0"' in node and
          '"--location"' in node and '"--proto", "=https"' in node,
          "checkpoint curl boundary/redirect/TLS policy missing")
    check("body.resize" in node and "oss << in.rdbuf()" not in
          node[node.index("size_t LoadCheckpointsFromUrl()"):],
          "checkpoint loader retains a second complete copy")
    check("TryAutoSnapshotBootstrap" not in node and
          "MaybePreferSnapshotAtStartup" not in node and
          "VELD_SNAPSHOT_MIRRORS" not in public_snapshot and
          '"https://veld.network/downloads/"' in public_snapshot and
          "latest.txt" not in public_snapshot,
          "snapshot acquisition is not pinned to the official fixed endpoint")
    check("RunProcessToBoundedFile" in public_snapshot and
          "PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES" in public_snapshot and
          "ValidateArchiveListings" in public_snapshot and
          "ValidateExtractedLevelDbTree" in public_snapshot,
          "snapshot transfer/extraction boundaries are incomplete")
    check("ValidateStoredChainOnly" in node and
          "VELD_ENABLE_SNAPSHOT_BOOTSTRAP" in node,
          "local non-public snapshot validation fixture was not preserved")
    check("Invoke-WebRequest" not in updater and "Expand-Archive" not in updater,
          "updater retains unbounded framework download/extraction")
    for required in (
        "ResponseHeadersRead", "AllowAutoRedirect = $false", "FileMode]::CreateNew",
        "MaxReleaseArchiveBytes", "MaxReleaseExpandedBytes",
        "Expand-BoundedReleaseArchive", "CancellationTokenSource",
    ):
        check(required in updater, f"updater boundary missing {required}")
    check("Get-BoundedHttpsFile" in tor_setup and
          "ResponseHeadersRead" in tor_setup and
          "AllowAutoRedirect = $false" in tor_setup and
          "TOR_MAX_ARCHIVE_BYTES" in tor_setup and
          "FileMode]::CreateNew" in tor_setup,
          "Tor bundle transfer is not bounded at the response stream")
    check("Invoke-WebRequest" not in tor_setup and
          "Invoke-WebRequest" not in mining_launcher and
          "Invoke-WebRequest" not in validator_launcher,
          "a shipped launcher retains an unbounded live download")
    check("tor-setup.ps1" in updater and "tor-watchdog.ps1" in updater,
          "signed updater does not require packaged Tor support files")
    tor_setup_hash = hashlib.sha256((ROOT / "pkg" / "tor-setup.ps1").read_bytes()).hexdigest()
    check(tor_setup_hash in mining_launcher and tor_setup_hash in validator_launcher,
          "launchers do not pin the exact packaged Tor setup helper")

    with tempfile.TemporaryDirectory(prefix="veld-f8-download-") as temporary:
        temp = Path(temporary)
        binary = temp / ("daybreak_bounded_download_tests.exe"
                         if os.name == "nt" else "daybreak_bounded_download_tests")
        build_command = [compiler(), "-std=c++20", "-O2", "-pthread"]
        if os.name == "nt":
            build_command.append("-static")
        build_command += [str(SOURCE), "-o", str(binary)]
        build = subprocess.run(
            build_command,
            cwd=ROOT, text=True, capture_output=True, timeout=120,
        )
        check(build.returncode == 0, f"bounded helper build failed: {build.stderr}")
        unit = subprocess.run([str(binary)], cwd=ROOT, text=True,
                              capture_output=True, timeout=20)
        check(unit.returncode == 0, unit.stderr)
        check("PASS daybreak_bounded_download_tests checks=21" in unit.stdout,
              f"unexpected helper checks: {unit.stdout}")

        maximum = 65536

        def oversized_length(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n"
                b"Connection: close\r\n\r\n")
            time.sleep(0.1)

        path = temp / "oversized-length.bin"
        with OneRequestServer(oversized_length) as server:
            status, exit_code, received, exists = fetch(
                binary, server, path, maximum, 2000)
        check(status == 8 and exit_code != 0,
              "oversized Content-Length was not rejected by curl preflight")
        check(received == 0 and exists == 0 and not path.exists(),
              "oversized Content-Length left body/partial file")

        def oversized_chunked(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                         b"Connection: close\r\n\r\n")
            for part in (b"A" * 32768, b"B" * 32768, b"C"):
                conn.sendall(f"{len(part):X}\r\n".encode() + part + b"\r\n")
            conn.sendall(b"0\r\n\r\n")

        path = temp / "oversized-chunked.bin"
        with OneRequestServer(oversized_chunked) as server:
            status, exit_code, received, exists = fetch(
                binary, server, path, maximum, 2000)
        check(status in (5, 8) and exit_code != 0,
              "oversized chunked body was accepted")
        check(exists == 0 and not path.exists(),
              "oversized chunked partial file survived")

        def slow_stream(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
                         b"Connection: close\r\n\r\nX")
            time.sleep(0.8)

        path = temp / "slow.bin"
        with OneRequestServer(slow_stream) as server:
            started = time.monotonic()
            status, _exit_code, _received, exists = fetch(
                binary, server, path, maximum, 150)
            elapsed = time.monotonic() - started
        check(status == 4 and elapsed < 0.7, "slow response evaded deadline")
        check(exists == 0 and not path.exists(), "slow response partial survived")

        def redirect(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(
                f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{server.port}/final\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n".encode())

        path = temp / "redirect.bin"
        with OneRequestServer(redirect) as server:
            status, exit_code, _received, exists = fetch(
                binary, server, path, maximum, 2000)
        check(server.requests == 1 and status == 8 and exit_code != 0,
              "redirect was followed or accepted")
        check(exists == 0 and not path.exists(), "redirect partial survived")

        def malformed_length(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n"
                         b"Connection: close\r\n\r\nbody")

        path = temp / "malformed.bin"
        with OneRequestServer(malformed_length) as server:
            status, exit_code, _received, exists = fetch(
                binary, server, path, maximum, 2000)
        check(status == 8 and exit_code != 0 and exists == 0 and not path.exists(),
              "malformed length was accepted or left a partial")

        def reset_body(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n"
                         b"Connection: close\r\n\r\nshort")

        path = temp / "reset.bin"
        with OneRequestServer(reset_body) as server:
            status, exit_code, _received, exists = fetch(
                binary, server, path, maximum, 2000)
        check(status == 8 and exit_code != 0 and exists == 0 and not path.exists(),
              "connection reset was accepted or left a partial")

        exact_body = bytes((index % 251 for index in range(maximum)))

        def exact_response(conn: socket.socket, _request: bytes) -> None:
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {maximum}\r\n"
                "Connection: close\r\n\r\n".encode() + exact_body)

        path = temp / "exact.bin"
        with OneRequestServer(exact_response) as server:
            status, exit_code, received, exists = fetch(
                binary, server, path, maximum, 2000)
        check((status, exit_code, received, exists) == (0, 0, maximum, 1),
              "exact maximum response did not succeed")
        check(path.read_bytes() == exact_body, "exact response bytes changed")
        check(hashlib.sha256(path.read_bytes()).digest() ==
              hashlib.sha256(exact_body).digest(), "exact response digest mismatch")

    print(f"PASS daybreak_download_server_tests checks={checks}")


if __name__ == "__main__":
    main()
