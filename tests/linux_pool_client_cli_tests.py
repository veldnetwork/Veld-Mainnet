#!/usr/bin/env python3
"""Exercise the public Linux pool command against a disposable TLS gateway."""

import http.server
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time


ADDRESS = "VSVPeRwNp9MkdPgeq5YCNV3im7HUEks63z"


class Gateway(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.loads(body)
        self.requests.append((self.path, payload))
        if self.path == "/v1/register":
            result = {
                "ok": True,
                "result": {
                    "version": "veld-pool/1",
                    "account": "ab" * 16,
                    "worker_token": "cd" * 32,
                    "view_token": "ef" * 32,
                },
            }
            data = json.dumps(result, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *_args):
        pass


def run(binary, *args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          text=True, timeout=10)


def main(binary):
    assert run(binary, "--help").returncode == 0
    with tempfile.TemporaryDirectory(prefix="veld-linux-pool-cli-") as tmp:
        root = Path(tmp)
        for bad in (
            ("--pool", "http://localhost", "--payout", ADDRESS,
             "--threads", "1", "--state-dir", root / "bad-http"),
            ("--pool", "https://localhost", "--payout", ADDRESS,
             "--threads", "0", "--state-dir", root / "bad-threads"),
            ("--pool", "https://localhost", "--payout", "invalid",
             "--threads", "1", "--state-dir", root / "bad-address"),
            ("--pool", "https://localhost", "--payout", ADDRESS,
             "--threads", "1", "--state-dir", root / "duplicate",
             "--threads", "2"),
        ):
            assert run(binary, *bad).returncode != 0
        assert not any(root.glob("bad-*")) and not (root / "duplicate").exists()

        key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        state = root / "private-state"
        command = [str(binary), "--pool",
                   f"https://localhost:{server.server_port}", "--payout", ADDRESS,
                   "--threads", "1", "--state-dir", str(state),
                   "--ca-file", str(cert)]
        worker = subprocess.Popen(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            account = state / "pool-account.json"
            while time.monotonic() < deadline and not account.exists() and worker.poll() is None:
                time.sleep(0.05)
            assert account.exists(), (
                "pool registration did not persist; "
                f"exit={worker.poll()} stderr="
                f"{worker.stderr.read() if worker.poll() is not None else 'still running'}")
            saved = json.loads(account.read_text())
            assert saved["address"] == ADDRESS
            assert saved["endpoint"] == f"https://localhost:{server.server_port}"
            assert saved["account"] == "ab" * 16
            assert Gateway.requests[0] == ("/v1/register", {"address": ADDRESS})
            assert os.stat(state).st_mode & 0o077 == 0
            assert os.stat(account).st_mode & 0o077 == 0
        finally:
            worker.send_signal(signal.SIGTERM)
            worker.communicate(timeout=10)
            server.shutdown()
            server.server_close()
        assert worker.returncode == 0, "clean pool-worker stop failed"
        assert not (root / "bad-address").exists()
    print("PASS Linux pool CLI: strict options, authenticated local TLS registration,"
          " private account state and clean stop")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
