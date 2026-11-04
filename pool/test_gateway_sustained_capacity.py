"""Real TLS/IPC pressure and authenticated reverse-proxy identity."""

import concurrent.futures
import http.client
import json
from pathlib import Path
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from .gateway import Gateway
from .protocol import Refused


class GatewayCapacity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="veld-gateway-sustained-")
        self.root = Path(self.temp.name)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(self.root / "key.pem"),
                "-out",
                str(self.root / "cert.pem"),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        self.delay = 0
        self.received = 0
        owner = self

        class IPC(socketserver.StreamRequestHandler):
            def handle(self):
                request = json.loads(self.rfile.readline(16385))
                assert request["action"] == "work"
                owner.received += 1
                time.sleep(owner.delay)
                self.wfile.write(b'{"ok":true,"result":{"fixture":true}}\n')

        class IPCServer(socketserver.ThreadingUnixStreamServer):
            request_queue_size = 128

        self.ipc = IPCServer(str(self.root / "ipc.sock"), IPC)
        self.servers = [self.ipc]
        self.threads = []
        thread = threading.Thread(target=self.ipc.serve_forever, daemon=True)
        thread.start()
        self.threads.append(thread)

    def tearDown(self):
        for server in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)
        self.temp.cleanup()

    def start(self, proxy=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.root / "cert.pem", self.root / "key.pem")
        if proxy:
            context.load_verify_locations(cafile=str(self.root / "cert.pem"))
            context.verify_mode = ssl.CERT_REQUIRED
        options = {"trusted_proxy": True} if proxy else {}
        gateway = Gateway(("127.0.0.1", 0), context, str(self.root / "ipc.sock"), **options)
        self.servers.append(gateway)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        self.threads.append(thread)
        return gateway

    def connection(self, gateway, certificate=False):
        trust = ssl.create_default_context(cafile=str(self.root / "cert.pem"))
        if certificate:
            trust.load_cert_chain(self.root / "cert.pem", self.root / "key.pem")
        return http.client.HTTPSConnection(
            "127.0.0.1", gateway.server_port, context=trust, timeout=6
        )

    @staticmethod
    def request(connection, address=None):
        headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
        if address is not None:
            headers["X-Veld-Client-IP"] = address
        connection.request("POST", "/v1/work", b"{}", headers)
        response = connection.getresponse()
        response.read()
        return response.status

    def test_short_burst_above_handler_count_drains_without_tls_loss(self):
        gateway = self.start()
        self.delay = 0.5
        barrier = threading.Barrier(80)

        def request(_):
            connection = self.connection(gateway)
            try:
                barrier.wait(timeout=5)
                return self.request(connection)
            finally:
                connection.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as workers:
            outcomes = []
            for future in [workers.submit(request, i) for i in range(80)]:
                try:
                    outcomes.append(future.result(timeout=10))
                except Exception as error:
                    outcomes.append(type(error).__name__)
        self.assertEqual(outcomes, [200] * 80)

    def test_authenticated_proxy_clients_do_not_share_one_rate_budget(self):
        gateway = self.start(proxy=True)
        connection = self.connection(gateway, certificate=True)
        started = time.monotonic()
        try:
            statuses = [self.request(connection, f"192.0.2.{i % 40 + 1}") for i in range(800)]
            self.assertLess(time.monotonic() - started, 10, "exercise one rate window")
            self.assertEqual(statuses, [200] * 800)
            self.assertEqual(self.received, 800)
        finally:
            connection.close()

    def test_direct_client_cannot_spoof_proxy_identity(self):
        gateway = self.start()
        connection = self.connection(gateway)
        started = time.monotonic()
        try:
            statuses = [self.request(connection, f"192.0.2.{i % 40 + 1}") for i in range(401)]
            self.assertLess(time.monotonic() - started, 10)
            self.assertEqual(statuses, [200] * 400 + [429])
        finally:
            connection.close()

    def test_proxy_requires_certificate_and_one_valid_source_address(self):
        gateway = self.start(proxy=True)
        anonymous = self.connection(gateway)
        try:
            with self.assertRaises((OSError, http.client.HTTPException)):
                self.request(anonymous, "192.0.2.1")
        finally:
            anonymous.close()
        for value in (None, "not-an-address", "192.0.2.1, 192.0.2.2"):
            connection = self.connection(gateway, certificate=True)
            try:
                self.assertEqual(self.request(connection, value), 400)
            finally:
                connection.close()
        self.assertEqual(self.received, 0)

        connection = self.connection(gateway, certificate=True)
        try:
            connection.putrequest("POST", "/v1/work")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "2")
            connection.putheader("X-Veld-Client-IP", "192.0.2.1")
            connection.putheader("X-Veld-Client-IP", "192.0.2.2")
            connection.endheaders(b"{}")
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            self.assertEqual(self.received, 0)
        finally:
            connection.close()

    def test_proxy_mode_refuses_missing_tls_authentication_or_public_bind(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.assertRaises(Refused):
            Gateway(
                ("127.0.0.1", 0),
                context,
                str(self.root / "ipc.sock"),
                trusted_proxy=True,
            )
        context.verify_mode = ssl.CERT_REQUIRED
        with self.assertRaises(Refused):
            Gateway(("0.0.0.0", 0), context, str(self.root / "ipc.sock"), trusted_proxy=True)

    def test_proxy_one_client_keeps_its_rate_limit(self):
        gateway = self.start(proxy=True)
        connection = self.connection(gateway, certificate=True)
        started = time.monotonic()
        try:
            statuses = [self.request(connection, "2001:db8::1") for _ in range(401)]
            self.assertLess(time.monotonic() - started, 10)
            self.assertEqual(statuses, [200] * 400 + [429])
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
