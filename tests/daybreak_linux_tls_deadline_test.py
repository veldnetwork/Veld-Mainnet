#!/usr/bin/env python3
"""Linux OpenSSL transport deadline and authentication process test."""

from __future__ import annotations

import argparse
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time


BODY = b'{"jsonrpc":"2.0","result":7,"id":1}'


def run_checked(command: list[str], cwd: pathlib.Path) -> None:
    subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
    )


def make_certificates(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    ca_key = root / "ca.key"
    ca_cert = root / "ca.pem"
    leaf_key = root / "leaf.key"
    leaf_csr = root / "leaf.csr"
    leaf_cert = root / "leaf.pem"
    self_key = root / "self.key"
    self_cert = root / "self.pem"
    extensions = root / "leaf.ext"
    extensions.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost\n",
        encoding="ascii",
    )
    run_checked(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=Daybreak Test CA",
            "-keyout", str(ca_key), "-out", str(ca_cert),
        ],
        root,
    )
    run_checked(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost",
            "-keyout", str(leaf_key), "-out", str(leaf_csr),
        ],
        root,
    )
    run_checked(
        [
            "openssl", "x509", "-req", "-days", "1",
            "-in", str(leaf_csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial",
            "-extfile", str(extensions), "-out", str(leaf_cert),
        ],
        root,
    )
    run_checked(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(self_key), "-out", str(self_cert),
        ],
        root,
    )
    return ca_cert, leaf_cert, leaf_key, self_cert, self_key


class OneShotTlsServer:
    def __init__(
        self,
        cert: pathlib.Path,
        key: pathlib.Path,
        behavior: str,
    ) -> None:
        self.behavior = behavior
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certfile=cert, keyfile=key)
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    @staticmethod
    def _read_request(peer: ssl.SSLSocket) -> None:
        peer.settimeout(2)
        received = bytearray()
        while b"\r\n\r\n" not in received and len(received) < 65536:
            block = peer.recv(4096)
            if not block:
                break
            received.extend(block)

    def _serve(self) -> None:
        try:
            raw, _ = self.listener.accept()
            self.listener.close()
            if self.behavior == "handshake-stall":
                # Leave the TCP connection open without beginning TLS.
                time.sleep(1.5)
                raw.close()
                return
            with self.context.wrap_socket(raw, server_side=True) as peer:
                if self.behavior in {
                    "post-handshake-stall", "write-stall", "shutdown"
                }:
                    time.sleep(1.5)
                    return
                self._read_request(peer)
                if self.behavior == "header-stall":
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Len")
                    time.sleep(1.5)
                elif self.behavior == "body-stall":
                    peer.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
                        b"partial"
                    )
                    time.sleep(1.5)
                elif self.behavior == "trickle":
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 20":
                        peer.sendall(bytes([byte]))
                        time.sleep(0.04)
                elif self.behavior == "abrupt-eof":
                    response = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: " +
                        str(len(BODY)).encode("ascii") + b"\r\n\r\n" + BODY
                    )
                    peer.sendall(response)
                    descriptor = peer.detach()
                    os.close(descriptor)
                elif self.behavior == "redirect":
                    peer.sendall(
                        b"HTTP/1.1 302 Found\r\n"
                        b"Location: https://elsewhere.invalid/\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    peer.unwrap()
                elif self.behavior == "oversized":
                    peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                    chunk = b"x" * (1024 * 1024)
                    for _ in range(33):
                        peer.sendall(chunk)
                elif self.behavior == "complete":
                    peer.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: " +
                        str(len(BODY)).encode("ascii") + b"\r\n\r\n" + BODY
                    )
                    peer.unwrap()
                else:
                    raise AssertionError(f"unknown behavior: {self.behavior}")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError):
            # Deadline/error scenarios intentionally close while the peer is
            # stalled. The client verdict is authoritative for those cases.
            pass
        except BaseException as error:  # surfaced after the client returns
            self.error = error
        finally:
            try:
                self.listener.close()
            except OSError:
                pass


def run_client(
    binary: pathlib.Path,
    mode: str,
    host: str,
    port: int,
    deadline_ms: int,
    ca_cert: pathlib.Path | None,
) -> tuple[int, str]:
    environment = os.environ.copy()
    if ca_cert is None:
        environment.pop("SSL_CERT_FILE", None)
    else:
        environment["SSL_CERT_FILE"] = str(ca_cert)
    completed = subprocess.run(
        [str(binary), mode, host, str(port), str(deadline_ms)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    lines = completed.stdout.splitlines()
    elapsed = int(next(line for line in lines if line.startswith("elapsed_ms=")).split("=", 1)[1])
    result = next(line for line in lines if line.startswith("result=")).split("=", 1)[1]
    return elapsed, result


def exercise(
    binary: pathlib.Path,
    cert: pathlib.Path,
    key: pathlib.Path,
    ca: pathlib.Path | None,
    behavior: str,
    *,
    host: str = "localhost",
    deadline_ms: int = 350,
) -> tuple[int, str]:
    server = OneShotTlsServer(cert, key, behavior)
    server.start()
    elapsed, result = run_client(
        binary, behavior, host, server.port, deadline_ms, ca
    )
    if elapsed > 2000:
        raise AssertionError(f"{behavior} exceeded bounded runtime: {elapsed}ms")
    if server.error is not None:
        raise server.error
    return elapsed, result


def require(result: str, needle: str, label: str) -> None:
    if needle not in result:
        raise AssertionError(f"{label}: expected {needle!r}, got {result!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()
    binary = arguments.binary.resolve(strict=True)
    checks = 0

    with tempfile.TemporaryDirectory(prefix="daybreak-linux-tls-") as temporary:
        root = pathlib.Path(temporary)
        ca, cert, key, self_cert, self_key = make_certificates(root)

        _, result = exercise(binary, cert, key, ca, "complete", deadline_ms=1200)
        require(result, '"result":7', "trusted complete response")
        checks += 1

        for behavior in (
            "handshake-stall",
            "post-handshake-stall",
            "write-stall",
            "header-stall",
            "body-stall",
            "trickle",
        ):
            elapsed, result = exercise(binary, cert, key, ca, behavior)
            require(result, "total deadline exceeded", behavior)
            if elapsed < 200:
                raise AssertionError(f"{behavior}: deadline fired too early")
            checks += 1

        elapsed, result = run_client(
            binary, "resolver-busy", "localhost", 9, 350, ca
        )
        require(result, "total deadline exceeded", "resolver concurrency")
        if elapsed < 200 or elapsed > 2000:
            raise AssertionError(
                f"resolver concurrency deadline was not bounded: {elapsed}ms"
            )
        checks += 1

        elapsed, result = exercise(
            binary, cert, key, ca, "shutdown", deadline_ms=1200
        )
        require(result, "interrupted by shutdown", "shutdown")
        if elapsed > 700:
            raise AssertionError(f"shutdown interruption was slow: {elapsed}ms")
        checks += 1

        _, result = exercise(binary, cert, key, ca, "abrupt-eof")
        require(result, "TLS node response failed", "abrupt EOF")
        checks += 1

        _, result = exercise(binary, cert, key, ca, "redirect", deadline_ms=1200)
        require(result, "TLS node rejected request", "redirect")
        checks += 1

        _, result = exercise(binary, cert, key, ca, "oversized", deadline_ms=2500)
        require(result, "response too large", "oversized response")
        checks += 1

        _, result = exercise(
            binary, cert, key, ca, "complete", host="127.0.0.1",
            deadline_ms=1200
        )
        require(result, "certificate or hostname verification failed", "hostname mismatch")
        checks += 1

        _, result = exercise(
            binary, self_cert, self_key, None, "complete", deadline_ms=1200
        )
        require(result, "certificate or hostname verification failed", "self signed")
        checks += 1

        # Remote plaintext is rejected before opening a socket.
        plaintext = subprocess.run(
            [str(binary), "plaintext", "example.com", "80", "250"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        require(plaintext.stdout, "Invalid RPC endpoint", "remote plaintext")
        checks += 1

    print(
        "PASS daybreak_linux_tls_deadline_test "
        f"checks={checks} deadline_ms=350 private_material_retained=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
