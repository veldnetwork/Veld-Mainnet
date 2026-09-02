#!/usr/bin/env python3
"""Executable method-independent portal admission and slow-client fixture."""

from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "veld-miner-portal.py"
SPEC = importlib.util.spec_from_file_location("veld_miner_portal", SOURCE)
assert SPEC and SPEC.loader
PORTAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORTAL)

TOKEN = bytes(range(32))
PROXY_AUTH = "VeldProxy v1=" + TOKEN.hex()
checks = 0


def check(value: bool) -> None:
    global checks
    checks += 1
    if not value:
        raise AssertionError(f"check {checks} failed")


def wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def entry_count(server, identity: str, bucket: str) -> int:
    return len(server.limiter._entries.get((identity, bucket), ()))


def proxy_headers(client: str, authorization: str = PROXY_AUTH) -> dict[str, str]:
    return {
        "X-Veld-Proxy-Authorization": authorization,
        "X-Veld-Client-IP": client,
    }


with tempfile.TemporaryDirectory(prefix="veld-portal-admission-") as temp:
    server = PORTAL.PortalServer(
        ("127.0.0.1", 0),
        PORTAL.PortalStore(Path(temp) / "portal.sqlite3"),
        True,
        "127.0.0.1",
        TOKEN,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])

    def request(
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        expect_zero_work: bool = True,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        if expect_zero_work:
            check(wait_for(lambda: server.concurrent_budget.memory == 0))
        return status, payload

    def raw_request(payload: bytes) -> tuple[int, bytes]:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.settimeout(5)
        client.sendall(payload)
        response = bytearray()
        while True:
            block = client.recv(4096)
            if not block:
                break
            response.extend(block)
        client.close()
        first_line = bytes(response).split(b"\r\n", 1)[0]
        status = int(first_line.split()[1])
        return status, bytes(response)

    try:
        # Every syntactically valid method reaches central admission before
        # method dispatch.  Unsupported methods therefore spend exactly one
        # proxy/client/route/global request charge and one concurrent charge.
        server.limiter = PORTAL.RateLimiter()
        method_cases = (
            ("OPTIONS", "/healthz"),
            ("HEAD", "/healthz"),
            ("PUT", "/api/v1/login"),
            ("BREW", "/arbitrary"),
        )
        for method, path in method_cases:
            status, _ = request(
                method, path, proxy_headers("198.51.100.10")
            )
            check(status == 501)
        check(entry_count(server, "global", "requests") == len(method_cases))
        check(entry_count(server, "client:198.51.100.10", "unauthenticated") == 4)
        check(entry_count(server, "global", "route:/healthz") == 2)
        check(entry_count(server, "global", "route:/api/v1/login") == 1)
        check(entry_count(server, "global", "route:/other") == 1)
        check((server.concurrent_budget.memory, server.concurrent_budget.work) == (0, 0))

        # The central concurrent-work gate runs before unsupported-method
        # dispatch as well; no cached or delayed handler work survives denial.
        server.limiter = PORTAL.RateLimiter()
        check(server.concurrent_budget.acquire(128, 64))
        check(request(
            "OPTIONS", "/healthz", proxy_headers("198.51.100.13"),
            expect_zero_work=False,
        )[0] == 503)
        check((server.concurrent_budget.memory, server.concurrent_budget.work) == (128, 64))
        check(entry_count(server, "global", "requests") == 0)
        server.concurrent_budget.release(128, 64)
        check((server.concurrent_budget.memory, server.concurrent_budget.work) == (0, 0))

        # Supported GET and POST are not charged again inside their handlers.
        server.limiter = PORTAL.RateLimiter()
        check(request("GET", "/healthz", proxy_headers("198.51.100.11"))[0] == 200)
        check(request("POST", "/not-found", proxy_headers("198.51.100.11"))[0] == 401)
        check(entry_count(server, "global", "requests") == 2)
        check(entry_count(server, "client:198.51.100.11", "unauthenticated") == 2)
        check(entry_count(server, "global", "route:/healthz") == 1)
        check(entry_count(server, "global", "route:/other") == 1)

        # Wrong proxy metadata is rejected by the same boundary even on an
        # unsupported verb; it never receives a normal client/request charge.
        server.limiter = PORTAL.RateLimiter()
        wrong = "VeldProxy v1=" + "00" * 32
        check(request(
            "OPTIONS", "/healthz", proxy_headers("198.51.100.12", wrong)
        )[0] == 403)
        check(entry_count(server, "peer:127.0.0.1", "invalid-proxy") == 1)
        check(entry_count(server, "global", "invalid-proxy") == 1)
        check(entry_count(server, "global", "boundary-work") == 1)
        check(entry_count(server, "global", "requests") == 0)

        # Bad request lines and parser-detected header defects cannot reach a
        # method handler, so they spend direct-peer plus global malformed/work
        # charges at the pre-dispatch error boundary.
        server.limiter = PORTAL.RateLimiter()
        check(raw_request(b"GET / extra HTTP/1.1\r\n\r\n")[0] == 400)
        check(raw_request(
            b"GET /healthz HTTP/1.1\r\nHost: portal\r\nBad Header\r\n\r\n"
        )[0] == 400)
        check(entry_count(server, "peer:127.0.0.1", "malformed-request") == 2)
        check(entry_count(server, "global", "malformed-request") == 2)
        check(entry_count(server, "global", "malformed-work") == 2)
        check(entry_count(server, "global", "requests") == 0)

        # An exhausted malformed envelope changes parser failures to a
        # fail-closed 429 without allocating a new limiter key.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(300):
            check(server.limiter.allow("global", "malformed-request", 300, 60))
        check(raw_request(b"GET / extra HTTP/1.1\r\n\r\n")[0] == 429)
        check(entry_count(server, "global", "malformed-request") == 300)

        # The connection-rate budget is independent of request parsing.  A
        # client refused at that boundary cannot strand either pre-parse
        # accounting object.
        server.limiter = PORTAL.RateLimiter()
        for _ in range(PORTAL.PREPARSE_CONNECTIONS_PER_MINUTE):
            check(server.limiter.allow(
                "global", "preparse-connections",
                PORTAL.PREPARSE_CONNECTIONS_PER_MINUTE, 60,
            ))
        refused = socket.create_connection(("127.0.0.1", port), timeout=5)
        refused.settimeout(5)
        refused.sendall(b"GET /healthz HTTP/1.1\r\nHost: portal\r\n\r\n")
        try:
            connection_closed = refused.recv(1) == b""
        except (ConnectionAbortedError, ConnectionResetError):
            connection_closed = True
        check(connection_closed)
        refused.close()
        check(wait_for(
            lambda: server.preparse_budget.memory == 0
            and server.preparse_budget.work == 0
            and getattr(server.request_slots, "_value", -1)
            == PORTAL.REQUEST_CONCURRENCY
        ))

        # Sixty-four partial request lines occupy both the retained hard
        # pre-parse semaphore and the explicit global connection budget.  A
        # sixty-fifth connection is closed, and completing the partial lines
        # releases every charge.
        server.limiter = PORTAL.RateLimiter()
        partials: list[socket.socket] = []
        for _ in range(PORTAL.REQUEST_CONCURRENCY):
            client = socket.create_connection(("127.0.0.1", port), timeout=5)
            client.settimeout(5)
            client.sendall(b"G")
            partials.append(client)
        check(wait_for(
            lambda: (
                server.preparse_budget.memory == PORTAL.REQUEST_CONCURRENCY
                and server.preparse_budget.work == PORTAL.REQUEST_CONCURRENCY
            )
        ))
        check(getattr(server.request_slots, "_value", -1) == 0)
        overflow = socket.create_connection(("127.0.0.1", port), timeout=5)
        overflow.settimeout(5)
        overflow.sendall(b"G")
        try:
            overflow_closed = overflow.recv(1) == b""
        except (ConnectionAbortedError, ConnectionResetError):
            overflow_closed = True
        check(overflow_closed)
        overflow.close()
        check(server.preparse_budget.memory == PORTAL.REQUEST_CONCURRENCY)
        check(entry_count(
            server, "global", "preparse-connections"
        ) == PORTAL.REQUEST_CONCURRENCY)
        for client in partials:
            client.sendall(b"ET / extra HTTP/1.1\r\n\r\n")
        for client in partials:
            response = bytearray()
            while True:
                block = client.recv(4096)
                if not block:
                    break
                response.extend(block)
            check(
                bytes(response).startswith(b"HTTP/1.0 400 ")
                or bytes(response).startswith(b"HTTP/1.0 429 ")
            )
            client.close()
        check(wait_for(
            lambda: server.preparse_budget.memory == 0
            and server.preparse_budget.work == 0
            and getattr(server.request_slots, "_value", -1)
            == PORTAL.REQUEST_CONCURRENCY
        ))

        source = SOURCE.read_text(encoding="utf-8")
        check("def parse_request(self) -> bool:" in source)
        check("if not self.admit_or_reply(self._request_path):" in source)
        check("path = self._request_path" in source)
        check("memory_limit=REQUEST_CONCURRENCY" in source)
        check("threading.BoundedSemaphore(REQUEST_CONCURRENCY)" in source)
        check("self.preparse_budget.release(1, 1)" in source)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        check(not thread.is_alive())


print(
    f"PASS daybreak_portal_admission_boundary_tests checks={checks} "
    "methods_malformed_proxy_partial_double_charge=1"
)
