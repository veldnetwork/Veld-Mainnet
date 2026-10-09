"""Private authenticated update feed for disposable Windows CI machines only."""

from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class PrivateFeed:
    def __init__(self, target, output):
        assert os.environ.get("GITHUB_ACTIONS") == "true"
        self.output = output
        self.output.mkdir()
        self.rows = []
        self.server = None
        self.thread = None
        self.thumbprint = None
        self.hosts = Path(os.environ["SystemRoot"]) / "System32/drivers/etc/hosts"
        self.original = self.hosts.read_bytes()
        assert b"veld.network" not in self.original.lower()
        self.changed = (
            self.original + b"\r\n127.0.0.1 veld.network # disposable Veld update fixture\r\n"
        )
        self.payloads = {
            "/downloads/" + name: (target / name).read_bytes()
            for name in ("SHA256SUMS.txt", "SHA256SUMS.txt.sig", "CHANGES.txt")
        }
        feed = target.parent / "feed"
        for name in (
            "VeldClient-Windows-x64.zip",
            "VeldClient-Windows-x64.zip.sha256",
            "VeldClient-Windows-x64.zip.sha256.sig",
        ):
            self.payloads["/downloads/" + name] = (feed / name).read_bytes()

    def certificate(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable Veld CI feed")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("veld.network")]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        self.thumbprint = cert.fingerprint(hashes.SHA1()).hex()
        (self.output / "tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (self.output / "tls.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))
        (self.output / "tls.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        subprocess.run(
            ["certutil", "-user", "-addstore", "Root", str(self.output / "tls.cer")],
            check=True,
            capture_output=True,
            timeout=30,
        )

    def __enter__(self):
        try:
            self.certificate()
            fixture = self

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    payload = fixture.payloads.get(self.path)
                    host = self.headers.get("Host")
                    status = 200 if payload is not None and host == "veld.network" else 404
                    fixture.rows.append(
                        {
                            "utc": datetime.now(timezone.utc).isoformat(),
                            "path": self.path,
                            "host": host,
                            "status": status,
                            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                        }
                    )
                    self.send_response(status)
                    self.send_header("Content-Length", str(len(payload) if status == 200 else 0))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    if status == 200:
                        self.wfile.write(payload)

                def log_message(self, *args):
                    pass

            self.server = ThreadingHTTPServer(("127.0.0.1", 443), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.output / "tls.pem", self.output / "tls.key")
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.hosts.write_bytes(self.changed)
            subprocess.run(["ipconfig", "/flushdns"], check=True, capture_output=True, timeout=30)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.server is not None:
            if self.thread is not None:
                self.server.shutdown()
                self.thread.join(timeout=5)
            self.server.server_close()
        if self.hosts.read_bytes() == self.changed:
            self.hosts.write_bytes(self.original)
        assert self.hosts.read_bytes() == self.original, "Unexpected hosts-file mutation"
        if self.thumbprint:
            subprocess.run(
                ["certutil", "-user", "-delstore", "Root", self.thumbprint],
                check=True,
                capture_output=True,
                timeout=30,
            )
        (self.output / "requests.json").write_text(json.dumps(self.rows, indent=2) + "\n")
        (self.output / "cleanup.json").write_text(
            json.dumps(
                {
                    "hosts_restored": True,
                    "temporary_certificate_removed": bool(self.thumbprint),
                    "listener_stopped": True,
                    "scope": "Loopback TLS feed on disposable hosted runner; normal TLS and package signatures enforced",
                },
                indent=2,
            )
            + "\n"
        )
