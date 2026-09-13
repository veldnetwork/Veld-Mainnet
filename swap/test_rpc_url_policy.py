#!/usr/bin/env python3
import os
import io
import threading
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request

from swap.rpc_url_policy import (
    build_direct_requests_session,
    load_bounded_json_response,
    open_rpc_request,
    read_bounded_secret_file,
    run_bounded_subprocess,
    validate_backend_rpc_url,
    validate_loopback_http_rpc_url,
)


class RpcUrlPolicyTests(unittest.TestCase):
    def test_unsupported_runtime_and_nonfinite_timeout_refuse_before_launch(self):
        with mock.patch("swap.rpc_url_policy.subprocess.Popen") as launch:
            for timeout in (float("inf"), float("nan"), -1, True):
                with self.assertRaisesRegex(RuntimeError, "timeout is invalid"):
                    run_bounded_subprocess(["unused"], timeout=timeout, stdout_max=1024, stderr_max=1024)
            with mock.patch("swap.rpc_url_policy.os.name", "nt"):
                with self.assertRaisesRegex(RuntimeError, "POSIX bounded operator runtime"):
                    run_bounded_subprocess(["unused"], timeout=1, stdout_max=1024, stderr_max=1024)
            launch.assert_not_called()

    def test_secret_reader_rejects_permissions_links_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "rpc.token"
            secret.write_bytes(b"secret")
            secret.chmod(0o600)
            self.assertEqual(
                read_bounded_secret_file(str(secret), 6, "RPC token"),
                b"secret")
            secret.chmod(0o640)
            with self.assertRaises(RuntimeError):
                read_bounded_secret_file(str(secret), 6, "RPC token")
            secret.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(secret)
            with self.assertRaises(OSError):
                read_bounded_secret_file(str(link), 6, "RPC token")
            hardlink = Path(directory) / "hardlink"
            os.link(secret, hardlink)
            with self.assertRaises(RuntimeError):
                read_bounded_secret_file(str(secret), 6, "RPC token")
            hardlink.unlink()
            with self.assertRaises(RuntimeError):
                read_bounded_secret_file(str(secret), 5, "RPC token")

    def test_bounded_json_reader_rejects_oversize_duplicates_and_nonfinite(self):
        self.assertEqual(
            load_bounded_json_response(io.BytesIO(b'{"ok":true}'), 64),
            {"ok": True})
        bad = (
            (b'{"a":1,"a":2}', 64),
            (b'{"a":NaN}', 64),
            (b'{"a":1e999}', 64),
            (b'\xff', 64),
            (b'{"long":"1234567890"}', 8),
        )
        for payload, maximum in bad:
            with self.subTest(payload=payload, maximum=maximum):
                with self.assertRaises(ValueError):
                    load_bounded_json_response(
                        io.BytesIO(payload), maximum, "test response")

    def test_plaintext_is_exact_loopback_only(self):
        for url in (
            "http://127.0.0.1:8332",
            "http://localhost:8334/rpc",
            "http://[::1]:8334",
        ):
            with self.subTest(url=url):
                self.assertEqual(validate_backend_rpc_url(url), url)
        for url in (
            "http://127.0.0.2:8332",
            "http://localhost.example:8332",
            "http://192.0.2.10:8332",
            "http://[::ffff:127.0.0.1]:8332",
            "http://localhost.:8332",
            "http://localhost%2eexample:8332",
            "http://%6cocalhost:8332",
            "http://2130706433:8332",
            "http://127.1:8332",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    validate_backend_rpc_url(url)

    def test_remote_https_rejects_url_secrets_and_ambient_suffixes(self):
        self.assertEqual(
            validate_backend_rpc_url("https://rpc.example:443/veld"),
            "https://rpc.example:443/veld")
        for url in (
            "https://user:pass@rpc.example/",
            "https://rpc.example/?token=secret",
            "https://rpc.example/#fragment",
            "ftp://rpc.example/",
            "//rpc.example/",
            "https://rpc.example:99999/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_backend_rpc_url(url)

    def test_loopback_operator_policy_parses_authority_not_prefix(self):
        for url in (
            "http://127.0.0.1:8332",
            "http://localhost:8334/rpc",
            "http://[::1]:8334",
        ):
            with self.subTest(url=url):
                self.assertEqual(validate_loopback_http_rpc_url(url), url)
        for url in (
            "http://localhost:@evil.example/rpc",
            "http://127.0.0.1:8332@evil.example/rpc",
            "http://127.0.0.1\\@evil.example:8332/rpc",
            "http://localhost.example:8332/rpc",
            "http://localhost%2eexample:8332/rpc",
            "http://%6cocalhost:8332/rpc",
            "http://localhost.:8332/rpc",
            "http://2130706433:8332/rpc",
            "http://127.1:8332/rpc",
            "http://0177.0.0.1:8332/rpc",
            "http://[0:0:0:0:0:0:0:1]:8332/rpc",
            "http://[::ffff:127.0.0.1]:8332/rpc",
            "http://192.0.2.10:8332/rpc",
            "https://localhost:8332/rpc",
            "http://localhost:8332/rpc?token=secret",
            "http://localhost:8332/rpc#fragment",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_loopback_http_rpc_url(url)

    def test_rpc_transport_never_follows_redirect_or_ambient_proxy(self):
        class Target(BaseHTTPRequestHandler):
            hits = 0

            def do_GET(self):
                type(self).hits += 1
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def do_POST(self):
                self.do_GET()

            def log_message(self, *_args):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()

        target_url = "http://127.0.0.1:%d/stolen" % target.server_port

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        redirect_thread = threading.Thread(target=redirect.serve_forever,
                                           daemon=True)
        redirect_thread.start()
        try:
            request = Request(
                "http://127.0.0.1:%d/rpc" % redirect.server_port,
                data=b"{}", headers={"Authorization": "Bearer secret"})
            with self.assertRaisesRegex(HTTPError, "redirects are forbidden"):
                open_rpc_request(request, timeout=2)
            self.assertEqual(Target.hits, 0)

            # A poisoned service environment must not route even a loopback RPC
            # request through an attacker-selected proxy.
            with mock.patch.dict(os.environ, {
                    "HTTP_PROXY": target_url, "http_proxy": target_url,
                    "NO_PROXY": "", "no_proxy": ""}, clear=False):
                request = Request(
                    "http://127.0.0.1:%d/rpc" % redirect.server_port,
                    data=b"{}", headers={"Authorization": "Bearer secret"})
                with self.assertRaises(HTTPError):
                    open_rpc_request(request, timeout=2)
            self.assertEqual(Target.hits, 0)
        finally:
            redirect.shutdown(); redirect.server_close()
            target.shutdown(); target.server_close()
            redirect_thread.join(timeout=2); target_thread.join(timeout=2)

    def test_requests_transport_never_follows_redirect_or_ambient_proxy(self):
        class Target(BaseHTTPRequestHandler):
            hits = 0

            def do_POST(self):
                type(self).hits += 1
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        target_url = "http://127.0.0.1:%d/stolen" % target.server_port

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(307)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        redirect_thread = threading.Thread(target=redirect.serve_forever,
                                           daemon=True)
        redirect_thread.start()
        try:
            rpc_url = "http://127.0.0.1:%d/rpc" % redirect.server_port
            with mock.patch.dict(os.environ, {
                    "HTTP_PROXY": target_url, "http_proxy": target_url,
                    "NO_PROXY": "", "no_proxy": ""}, clear=False):
                session = build_direct_requests_session(rpc_url)
                self.assertFalse(session.trust_env)
                response = session.post(rpc_url, data=b"{}")
            self.assertEqual(response.status_code, 307)
            self.assertEqual(Target.hits, 0)
        finally:
            redirect.shutdown(); redirect.server_close()
            target.shutdown(); target.server_close()
            redirect_thread.join(timeout=2); target_thread.join(timeout=2)

    def test_all_funds_bearing_rpc_clients_share_the_transport_boundary(self):
        swap = Path(__file__).resolve().parent
        clients = (
            "veld_mintd.py", "veld_btcrelayd.py", "veld_anchord.py", "veld_signerd.py",
            "veld_redeemd.py", "veld_watchtowerd.py", "veld_wt_reserve.py",
            "veld_wrapd.py", "veld_spvmint.py",
        )
        for name in clients:
            with self.subTest(client=name):
                source = (swap / name).read_text(encoding="utf-8")
                self.assertTrue(
                    "open_rpc_request(" in source or
                    "build_direct_requests_session(" in source)
                self.assertTrue(
                    "validate_backend_rpc_url" in source or
                    "validate_loopback_http_rpc_url" in source)


if __name__ == "__main__":
    unittest.main()
