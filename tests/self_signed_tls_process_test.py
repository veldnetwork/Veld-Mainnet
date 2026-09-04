#!/usr/bin/env python3
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[1]
OPENSSL = Path(r"C:\msys64\clang64\bin\openssl.exe")
TEST_BINARY = ROOT / "tests" / "desktop_rpc_transport_tests.exe"


def main() -> int:
    if not OPENSSL.is_file() or not TEST_BINARY.is_file():
        raise RuntimeError("required local test dependency is missing")
    with tempfile.TemporaryDirectory(prefix="veld-security-test-self-signed-") as temp:
        temp_path = Path(temp)
        cert = temp_path / "cert.pem"
        key = temp_path / "key.pem"
        subprocess.run(
            [
                str(OPENSSL), "req", "-x509", "-newkey", "rsa:2048",
                "-sha256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost",
                "-keyout", str(key), "-out", str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)
        accepted = threading.Event()

        def serve() -> None:
            try:
                raw, _ = listener.accept()
                accepted.set()
                try:
                    with context.wrap_socket(raw, server_side=True) as secure:
                        secure.recv(4096)
                        secure.sendall(
                            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                        )
                except (ssl.SSLError, ConnectionError, OSError):
                    raw.close()
            finally:
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        env = os.environ.copy()
        env["PATH"] = str(OPENSSL.parent) + os.pathsep + env.get("PATH", "")
        env["VELD_TEST_SELF_SIGNED_TLS_PORT"] = str(listener.getsockname()[1])
        result = subprocess.run(
            [str(TEST_BINARY)], env=env, text=True, capture_output=True,
            timeout=30, check=False,
        )
        worker.join(timeout=15)
        if result.returncode != 0:
            raise RuntimeError(result.stdout + result.stderr)
        if not accepted.is_set():
            raise RuntimeError("WinHTTP never reached the bounded TLS peer")
        if "self_signed_rejected=1" not in result.stdout:
            raise RuntimeError("self-signed certificate was not rejected")
        print(result.stdout.strip())
        print("PASS self_signed_tls_process_test accepted=1 rejected=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
