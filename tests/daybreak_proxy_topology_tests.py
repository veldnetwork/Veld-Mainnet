#!/usr/bin/env python3
"""Executable loopback reverse-proxy boundary and quota topology fixture."""

import http.client
import importlib.util
import json
import base64
import tempfile
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "veld-miner-portal.py"
TEMPLATE = ROOT / "pkg" / "reverse-proxy" / "veld-public-services.nginx.conf.template"
SPEC = importlib.util.spec_from_file_location("veld_miner_portal_topology", SOURCE)
assert SPEC and SPEC.loader
PORTAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORTAL)

checks = 0


def check(value: bool) -> None:
    global checks
    checks += 1
    if not value:
        raise AssertionError(f"check {checks} failed")


TOKEN = bytes(range(32))
AUTH = "VeldProxy v1=" + TOKEN.hex()


def proxy_headers(client: str, auth: str = AUTH) -> dict[str, str]:
    return {
        "X-Veld-Proxy-Authorization": auth,
        "X-Veld-Client-IP": client,
    }


with tempfile.TemporaryDirectory(prefix="veld-portal-proxy-") as temp:
    database = Path(temp) / "portal.sqlite3"
    server = PORTAL.PortalServer(
        ("127.0.0.1", 0), PORTAL.PortalStore(database), True,
        "127.0.0.1", TOKEN,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def request(
        path: str = "/healthz",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_headers = dict(response.getheaders())
        payload = response.read()
        connection.close()
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            value = {}
        return response.status, value, response_headers

    try:
        # Direct loopback is not free and cannot select a forwarding identity.
        check(request()[0] == 200)
        check(request(headers={"X-Forwarded-For": "198.51.100.9"})[0] == 403)
        check(request(headers={"X-Real-IP": "198.51.100.9"})[0] == 403)
        check(request(headers={"X-Veld-Client-IP": "198.51.100.9"})[0] == 403)

        # Wrong authentication and a correct explicitly trusted proxy.
        check(request(headers=proxy_headers(
            "198.51.100.10", "VeldProxy v1=" + "00" * 32))[0] == 403)
        check(request(headers=proxy_headers("198.51.100.10"))[0] == 200)
        check(request(headers=proxy_headers("2001:0db8::10"))[0] == 200)

        server.limiter = PORTAL.RateLimiter()
        for _ in range(59):
            check(server.limiter.allow(
                "peer:127.0.0.1", "invalid-proxy", 60, 60
            ))
        check(request(headers=proxy_headers(
            "198.51.100.11", "VeldProxy v1=" + "00" * 32))[0] == 403)
        check(request(headers=proxy_headers(
            "198.51.100.11", "VeldProxy v1=" + "00" * 32))[0] == 429)
        check(request(headers=proxy_headers("198.51.100.11"))[0] == 200)

        # Establish real verified account, session, bearer, and device
        # principals through the same loopback proxy topology.
        register_body = json.dumps({
            "account": "operator",
            "password": "correct horse battery staple",
        }, separators=(",", ":")).encode()
        register_headers = proxy_headers("198.51.100.40") | {
            "Content-Type": "application/json",
            "Content-Length": str(len(register_body)),
        }
        register_status, register_value, register_response_headers = request(
            "/api/v1/register", "POST", register_headers, register_body
        )
        check(register_status == 200)
        check(isinstance(register_value.get("csrf"), str))
        cookie = register_response_headers["Set-Cookie"].split(";", 1)[0]
        session_headers = proxy_headers("198.51.100.40") | {"Cookie": cookie}
        check(request("/api/v1/devices", headers=session_headers)[0] == 200)

        device_token = "A" * 43
        report_value = {
            "portal_protocol": 3,
            "name": "Topology fixture",
            "version": "3.0.0",
            "height": 0,
            "sync_lag": 0,
            "hashrate": 0,
            "workers": 0,
            "peers": 0,
            "inbound": 0,
            "blocks": 0,
            "mining_state": "Paused",
            "snapshot": {},
        }
        report_body = json.dumps(report_value, separators=(",", ":")).encode()
        report_status, report_response, _ = request(
            "/api/v1/device/report", "POST",
            proxy_headers("198.51.100.41") | {
                "Authorization": "Bearer " + device_token,
                "Content-Type": "application/json",
                "Content-Length": str(len(report_body)),
            }, report_body,
        )
        check(report_status == 200)
        check(isinstance(report_response.get("device_id"), int))
        check(isinstance(report_response.get("pair_code"), str))

        private_key = PORTAL.ec.generate_private_key(PORTAL.ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        encode_coordinate = lambda value: base64.urlsafe_b64encode(
            value.to_bytes(32, "big")
        ).rstrip(b"=").decode("ascii")
        claim_value = {
            "code": report_response["pair_code"],
            "command_key": {
                "kty": "EC",
                "crv": "P-256",
                "x": encode_coordinate(numbers.x),
                "y": encode_coordinate(numbers.y),
            },
        }
        claim_body = json.dumps(claim_value, separators=(",", ":")).encode()
        authenticated_headers = session_headers | {
            "X-CSRF-Token": register_value["csrf"],
            "Content-Type": "application/json",
            "Content-Length": str(len(claim_body)),
        }
        check(request(
            "/api/v1/devices/claim", "POST", authenticated_headers, claim_body
        )[0] == 200)
        rename_body = json.dumps({
            "id": report_response["device_id"], "name": "Renamed fixture"
        }, separators=(",", ":")).encode()
        rename_headers = session_headers | {
            "X-CSRF-Token": register_value["csrf"],
            "Content-Type": "application/json",
            "Content-Length": str(len(rename_body)),
        }
        check(request(
            "/api/v1/devices/rename", "POST", rename_headers, rename_body
        )[0] == 200)

        reset_headers = proxy_headers("198.51.100.41") | {
            "Authorization": "Bearer " + device_token,
            "Content-Type": "application/json",
            "Content-Length": "2",
        }
        reset_status, reset_value, _ = request(
            "/api/v1/device/reset-pairing", "POST", reset_headers, b"{}"
        )
        check(reset_status == 200)
        check(isinstance(reset_value.get("pair_code"), str))
        check(reset_value["pair_code"] != report_response["pair_code"])
        devices_status, devices_value, _ = request(
            "/api/v1/devices", headers=session_headers
        )
        check(devices_status == 200 and devices_value["devices"] == [])
        report_status, report_after_reset, _ = request(
            "/api/v1/device/report", "POST",
            proxy_headers("198.51.100.41") | {
                "Authorization": "Bearer " + device_token,
                "Content-Type": "application/json",
                "Content-Length": str(len(report_body)),
            }, report_body,
        )
        check(report_status == 200)
        check(report_after_reset["paired"] is False)
        check(report_after_reset["pair_code"] == reset_value["pair_code"])

        # Malformed bearer traffic spends only its unauthenticated client and
        # global request envelope; it cannot consume the known device quota.
        server.limiter = PORTAL.RateLimiter()
        invalid_report_headers = proxy_headers("198.51.100.50") | {
            "Authorization": "Bearer invalid",
            "Content-Type": "application/json",
            "Content-Length": "2",
        }
        for _ in range(119):
            check(server.limiter.allow(
                "client:198.51.100.50", "unauthenticated", 120, 60
            ))
        check(request(
            "/api/v1/device/report", "POST", invalid_report_headers, b"{}"
        )[0] == 401)
        check(request(
            "/api/v1/device/report", "POST", invalid_report_headers, b"{}"
        )[0] == 429)
        check(request(
            "/api/v1/device/report", "POST",
            proxy_headers("198.51.100.51") | {
                "Authorization": "Bearer " + device_token,
                "Content-Type": "application/json",
                "Content-Length": str(len(report_body)),
            }, report_body,
        )[0] == 200)

        # Exhausting client A cannot spend client B's independent allowance.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(120):
            check(server.limiter.allow(
                "client:198.51.100.20", "unauthenticated", 120, 60
            ))
        check(request(headers=proxy_headers("198.51.100.20"))[0] == 429)
        check(request(headers=proxy_headers("198.51.100.21"))[0] == 200)

        # With authenticated forwarding absent, the proxy/direct-loopback peer
        # is one shared bounded identity, not an exemption.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(120):
            check(server.limiter.allow(
                "peer:127.0.0.1", "unauthenticated", 120, 60
            ))
        check(request()[0] == 429)
        check(request(headers=proxy_headers("198.51.100.22"))[0] == 200)

        # Per-route and global request exhaustion fail closed.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(1200):
            check(server.limiter.allow("global", "route:/healthz", 1200, 60))
        check(request(headers=proxy_headers("198.51.100.23"))[0] == 429)
        server.limiter = PORTAL.RateLimiter()
        for _ in range(6000):
            check(server.limiter.allow("global", "requests", 6000, 60))
        check(request(headers=proxy_headers("198.51.100.24"))[0] == 429)

        # Expensive routes consume the concurrent memory/work envelope before
        # parsing or password/device work.
        server.limiter = PORTAL.RateLimiter()
        check(server.concurrent_budget.acquire(128, 64))
        login_body = b'{"account":"operator","password":"invalid-password"}'
        login_headers = proxy_headers("198.51.100.25") | {
            "Content-Type": "application/json",
            "Content-Length": str(len(login_body)),
        }
        check(request("/api/v1/login", "POST", login_headers, login_body)[0] == 503)
        server.concurrent_budget.release(128, 64)
        check(request(
            "/api/v1/device/report", "POST",
            proxy_headers("198.51.100.26") | {
                "Authorization": "Bearer invalid",
                "Content-Type": "application/json",
                "Content-Length": "2",
            }, b"{}",
        )[0] == 401)

        # Password verification, device-report, and malformed-request work
        # each have an independent global budget exercised through HTTP.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(120):
            check(server.limiter.allow(
                "portal-password-global", "password-verification", 120, 600
            ))
        check(request("/api/v1/login", "POST", login_headers, login_body)[0] == 429)

        server.limiter = PORTAL.RateLimiter()
        for _ in range(2000):
            check(server.limiter.allow("global", "device-report", 2000, 60))
        report_headers = proxy_headers("198.51.100.27") | {
            "Authorization": "Bearer " + "A" * 43,
            "Content-Type": "application/json",
            "Content-Length": "2",
        }
        check(request(
            "/api/v1/device/report", "POST", report_headers, b"{}"
        )[0] == 429)

        server.limiter = PORTAL.RateLimiter()
        for _ in range(300):
            check(server.limiter.allow("global", "malformed-request", 300, 60))
        malformed = b"{"
        malformed_headers = proxy_headers("198.51.100.28") | {
            "Content-Type": "application/json",
            "Content-Length": "1",
        }
        check(request(
            "/api/v1/login", "POST", malformed_headers, malformed
        )[0] == 429)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        check(not thread.is_alive())

template = TEMPLATE.read_text(encoding="utf-8")
check("$remote_addr" in template)
check("X-Veld-Client-IP" in template)
check("X-Veld-Proxy-Authorization" in template)
check('proxy_set_header X-Forwarded-For ""' in template)
check("limit_req_zone" in template and "limit_conn_zone" in template)
check("--trusted-proxy-peer 127.0.0.1" in template)
check("explorer-proxy.conf" in template)

print(f"PASS daybreak_proxy_topology_tests checks={checks} "
      "actual_loopback_trusted_proxy_global_route_work_budgets=1")
