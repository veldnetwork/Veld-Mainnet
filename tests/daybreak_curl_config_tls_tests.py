#!/usr/bin/env python3
"""Prove curl configuration cannot disable node TLS verification."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[1]
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def executable(name: str, candidates: list[str]) -> str:
    found = shutil.which(name)
    if found:
        return found
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError(f"required executable unavailable: {name}")


class SelfSignedHttpsServer:
    def __init__(self, certificate: Path, private_key: Path,
                 expected_connections: int) -> None:
        self.expected_connections = expected_connections
        self.connections = 0
        self.error: BaseException | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(expected_connections + 1)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, private_key)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "SelfSignedHttpsServer":
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            self.listener.settimeout(8)
            while self.connections < self.expected_connections:
                connection, _ = self.listener.accept()
                self.connections += 1
                try:
                    with self.context.wrap_socket(
                            connection, server_side=True) as tls:
                        tls.settimeout(3)
                        request = bytearray()
                        while b"\r\n\r\n" not in request and len(request) < 65536:
                            part = tls.recv(4096)
                            if not part:
                                break
                            request.extend(part)
                        body = b"{}"
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: 2\r\nConnection: close\r\n\r\n" + body
                        )
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                    connection.close()
        except BaseException as exc:
            self.error = exc
        finally:
            self.listener.close()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.thread.join(timeout=10)
        check(not self.thread.is_alive(), "TLS fixture did not finish")
        if self.error is not None:
            raise self.error
        check(self.connections == self.expected_connections,
              "TLS fixture did not observe both curl handshakes")


def main() -> None:
    node = (ROOT / "include" / "node" / "node.h").read_text("utf-8")
    node_main = (ROOT / "src" / "veld-node.cpp").read_text("utf-8")
    check('{curl_executable, "--disable", "-fsS"' in node,
          "oracle curl does not disable user configuration first")
    check('{curl_executable, "--disable", "--fail", "--silent"' in node,
          "checkpoint curl does not disable user configuration first")
    check(node.count("compat::TrustedSystemCurlExecutable()") == 2 and
          node.count("if (curl_executable.empty())") == 2 and
          '{"curl"' not in node,
          "node curl executable identity is not trusted and fail-closed")
    check(node.count('"--disable"') == 2,
          "unexpected or missing node curl configuration interlock")
    check("rd(argv[2], 8u * 1024u * 1024u" in node_main,
          "release manifest verifier ceiling differs from updater transfer cap")

    curl = executable("curl", [r"C:\Windows\System32\curl.exe"])
    openssl = executable(
        "openssl",
        [r"C:\msys64\clang64\bin\openssl.exe",
         r"C:\Program Files\Git\usr\bin\openssl.exe"],
    )

    with tempfile.TemporaryDirectory(prefix="veld-f8-curl-tls-") as temporary:
        temp = Path(temporary)
        certificate = temp / "self-signed.pem"
        private_key = temp / "self-signed.key"
        generated = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256",
             "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-keyout", str(private_key), "-out", str(certificate)],
            cwd=temp, capture_output=True, timeout=30,
        )
        check(generated.returncode == 0,
              f"self-signed certificate generation failed: {generated.stderr!r}")

        curl_home = temp / "curl-home"
        curl_home.mkdir()
        for name in (".curlrc", "_curlrc"):
            (curl_home / name).write_text("insecure\n", encoding="ascii")
        environment = os.environ.copy()
        environment.update({
            "CURL_HOME": str(curl_home),
            "HOME": str(curl_home),
            "USERPROFILE": str(curl_home),
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        environment.pop("CURL_CA_BUNDLE", None)
        environment.pop("SSL_CERT_FILE", None)

        with SelfSignedHttpsServer(certificate, private_key, 2) as server:
            url = f"https://127.0.0.1:{server.port}/fixture"
            options = [
                "--fail", "--silent", "--show-error",
                "--connect-timeout", "2", "--max-time", "5",
                "--proto", "=https", url,
            ]
            configured = subprocess.run(
                [curl, *options], env=environment,
                capture_output=True, timeout=10,
            )
            check(configured.returncode == 0 and configured.stdout == b"{}",
                  "negative control did not prove insecure curlrc was active")

            strict = subprocess.run(
                [curl, "--disable", *options], env=environment,
                capture_output=True, timeout=10,
            )
            check(strict.returncode != 0,
                  "--disable allowed curlrc to bypass self-signed TLS refusal")
            check(strict.stdout == b"",
                  "TLS-refused request returned attacker-controlled body bytes")

    print(f"PASS daybreak_curl_config_tls_tests checks={checks}")


if __name__ == "__main__":
    main()
