"""Bounded real-TLS ingress burst against disposable Unix IPC."""

import concurrent.futures
import http.client
import json
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from .gateway import Gateway


class BurstCapacity(unittest.TestCase):
    def test_35_simultaneous_requests_have_bounded_success(self):
        with tempfile.TemporaryDirectory(prefix="veld-gateway-burst-") as temp:
            root = Path(temp)
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-keyout", str(root / "key.pem"), "-out",
                 str(root / "cert.pem"), "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                check=True, capture_output=True)

            class IPC(socketserver.StreamRequestHandler):
                def handle(self):
                    request = json.loads(self.rfile.readline(16385))
                    assert request == {"action": "work", "payload": {}}
                    time.sleep(3)
                    self.wfile.write(b'{"ok":true,"result":{"fixture":true}}\n')

            class IPCServer(socketserver.ThreadingUnixStreamServer):
                request_queue_size = 64

            ipc = IPCServer(str(root / "ipc.sock"), IPC)
            ipc_thread = threading.Thread(target=ipc.serve_forever, daemon=True)
            ipc_thread.start()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(root / "cert.pem", root / "key.pem")
            gateway = Gateway(("127.0.0.1", 0), context, str(root / "ipc.sock"))
            gateway_thread = threading.Thread(target=gateway.serve_forever,
                                              daemon=True)
            gateway_thread.start()
            trust = ssl.create_default_context(cafile=str(root / "cert.pem"))
            barrier = threading.Barrier(35)

            def request(_):
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", gateway.server_port, context=trust, timeout=8)
                try:
                    barrier.wait(timeout=5)
                    connection.request("POST", "/v1/work", b"{}",
                                       {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, json.loads(response.read(16385))
                finally:
                    connection.close()

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=35) as pool:
                    futures = [pool.submit(request, n) for n in range(35)]
                    outcomes = []
                    for future in futures:
                        try:
                            outcomes.append(future.result(timeout=12))
                        except Exception as error:
                            outcomes.append((type(error).__name__, str(error)[:80]))
                expected = (200, {"ok": True, "result": {"fixture": True}})
                failed = [(n, value) for n, value in enumerate(outcomes)
                          if value != expected]
                self.assertFalse(failed, f"{len(failed)} of 35 failed: {failed}")
            finally:
                gateway.shutdown()
                gateway.server_close()
                gateway_thread.join(timeout=5)
                ipc.shutdown()
                ipc.server_close()
                ipc_thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
