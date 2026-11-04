#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "veld-miner-portal.py"
SPEC = importlib.util.spec_from_file_location("veld_miner_portal", SOURCE)
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


def handler(limiter, address="127.0.0.1", proxy=None, headers=None, store=None):
    result = object.__new__(PORTAL.PortalHandler)
    result.server = SimpleNamespace(
        limiter=limiter,
        proxy=proxy or PORTAL.TrustedProxyBoundary(),
        store=store,
    )
    result.client_address = (address, 41000)
    result.headers = headers or {}
    result._client_rate_identity = None
    return result


check(PORTAL.rate_identity("127.000.000.001") == "unknown")
check(PORTAL.rate_identity("127.0.0.1") == "127.0.0.1")
check(PORTAL.rate_identity("2001:0db8::1") == "2001:db8::1")
check(PORTAL.rate_identity("::ffff:192.0.2.7") == "192.0.2.7")
check(PORTAL.rate_identity("not-an-address") == "unknown")
check(PORTAL.account_rate_identity("Miner") ==
      PORTAL.account_rate_identity("mINER"))
check(PORTAL.account_rate_identity("Miner") !=
      PORTAL.account_rate_identity("Miner2"))
check(len(PORTAL.account_rate_identity("a" * 48)) == 72)

if os.name != "nt":
    with tempfile.TemporaryDirectory(prefix="veld-proxy-token-") as temp:
        token_path = Path(temp) / "proxy.token"
        token_path.write_text(TOKEN.hex() + "\n", encoding="ascii")
        os.chmod(token_path, 0o600)
        check(PORTAL.load_proxy_token(token_path) == TOKEN)
        os.chmod(token_path, 0o644)
        try:
            PORTAL.load_proxy_token(token_path)
            check(False)
        except ValueError:
            check(True)
        os.chmod(token_path, 0o600)
        hardlink_path = Path(temp) / "proxy-hardlink.token"
        os.link(token_path, hardlink_path)
        try:
            PORTAL.load_proxy_token(token_path)
            check(False)
        except ValueError:
            check(True)

boundary = PORTAL.TrustedProxyBoundary("127.0.0.1", TOKEN)
check(boundary.resolve("127.0.0.1", {}) == "peer:127.0.0.1")
check(boundary.resolve("127.0.0.1", {
    "X-Veld-Proxy-Authorization": AUTH,
    "X-Veld-Client-IP": "2001:0db8::1",
}) == "client:2001:db8::1")
check(boundary.resolve("127.0.0.1", {
    "X-Veld-Proxy-Authorization": AUTH,
    "X-Veld-Client-IP": "::ffff:192.0.2.7",
}) == "client:192.0.2.7")
for peer, headers in (
    ("127.0.0.1", {"X-Forwarded-For": "198.51.100.9"}),
    ("127.0.0.1", {"X-Real-IP": "198.51.100.9"}),
    ("127.0.0.1", {"X-Veld-Client-IP": "198.51.100.9"}),
    ("127.0.0.1", {
        "X-Veld-Proxy-Authorization": "VeldProxy v1=" + "00" * 32,
        "X-Veld-Client-IP": "198.51.100.9",
    }),
    ("127.0.0.2", {
        "X-Veld-Proxy-Authorization": AUTH,
        "X-Veld-Client-IP": "198.51.100.9",
    }),
):
    try:
        boundary.resolve(peer, headers)
        check(False)
    except PORTAL.ProxyMetadataError:
        check(True)

# Account, global password-work, and client charges are one atomic operation.
registration_limiter = PORTAL.RateLimiter()
registration = handler(registration_limiter)
for spelling in ("Miner", "MINER", "mInEr"):
    check(registration.auth_rate(spelling, registration=True))
check(not registration.auth_rate("miner", registration=True))

split_global = PORTAL.RateLimiter()
first_client = handler(split_global, "198.51.100.1")
second_client = handler(split_global, "198.51.100.2")
third_client = handler(split_global, "198.51.100.3")
for index in range(12):
    check(first_client.auth_rate(f"first{index}", registration=True))
check(not first_client.auth_rate("firstblocked", registration=True))
for index in range(12):
    check(second_client.auth_rate(f"second{index}", registration=True))
check(not third_client.auth_rate("globalblocked", registration=True))

atomic = PORTAL.RateLimiter()
check(atomic.allow("victim", "account", 1, 60))
check(not atomic.allow_many((
    ("global", "auth", 100, 60),
    ("victim", "account", 1, 60),
)))
check(("global", "auth") not in atomic._entries)


class DeviceStore:
    @staticmethod
    def device_belongs(account_id, device_id):
        return account_id == 7 and device_id in {101, 102}


device_limiter = PORTAL.RateLimiter()
device_handler = handler(device_limiter, store=DeviceStore())
for _ in range(120):
    check(device_handler.device_rate(7, 101))
check(not device_handler.device_rate(7, 101))
check(device_handler.device_rate(7, 102))
check(not device_handler.device_rate(7, 999))
check(("device:999", "device-operation") not in device_limiter._entries)

global_limiter = PORTAL.RateLimiter()
for index in range(24):
    candidate = handler(global_limiter, f"198.51.100.{index + 1}")
    check(candidate.auth_rate(f"account{index}", registration=True))
candidate = handler(global_limiter, "203.0.113.200")
check(not candidate.auth_rate("account24", registration=True))

bounded = PORTAL.RateLimiter()
for index in range(8192):
    check(bounded.allow(f"198.18.{index // 256}.{index % 256}",
                        "bounded", 1, 3600))
check(not bounded.allow("203.0.113.250", "bounded", 1, 3600))
check(len(bounded._entries) == 8192)

original_monotonic = PORTAL.time.monotonic
clock = [100.0]
PORTAL.time.monotonic = lambda: clock[0]
try:
    expiring = PORTAL.RateLimiter()
    check(expiring.allow("client", "short", 1, 10))
    check(not expiring.allow("client", "short", 1, 10))
    clock[0] = 111.0
    check(expiring.allow("client", "short", 1, 10))
    pruning = PORTAL.RateLimiter()
    clock[0] = 200.0
    for index in range(4096):
        check(pruning.allow(f"client:{index}", "stale", 1, 3600))
    clock[0] = 3801.0
    check(pruning.allow("fresh", "stale", 1, 3600))
    check(len(pruning._entries) == 1)
finally:
    PORTAL.time.monotonic = original_monotonic

budget = PORTAL.ConcurrentBudget(memory_limit=8, work_limit=4)
check(budget.acquire(4, 2))
check(budget.acquire(4, 2))
check(not budget.acquire(1, 1))
budget.release(4, 2)
check(budget.acquire(4, 2))
budget.release(4, 2)
budget.release(4, 2)
check((budget.memory, budget.work, budget.history) == (0, 0, 0))

concurrent = PORTAL.ConcurrentBudget(memory_limit=16, work_limit=16)
start = threading.Barrier(33)
attempted = threading.Barrier(33)
release = threading.Event()
results = [False] * 32


def concurrent_attempt(index: int) -> None:
    start.wait()
    results[index] = concurrent.acquire(4, 4, history=True)
    attempted.wait()
    if results[index]:
        release.wait()
        concurrent.release(4, 4, history=True)


threads = [
    threading.Thread(target=concurrent_attempt, args=(index,))
    for index in range(len(results))
]
for thread in threads:
    thread.start()
start.wait()
attempted.wait()
check(sum(results) == 4)
check((concurrent.memory, concurrent.work, concurrent.history) == (16, 16, 4))
release.set()
for thread in threads:
    thread.join(timeout=5)
check(all(not thread.is_alive() for thread in threads))
check((concurrent.memory, concurrent.work, concurrent.history) == (0, 0, 0))

source = SOURCE.read_text(encoding="utf-8")
route_start = source.index('if path in {"/api/v1/register", "/api/v1/login"}:')
route_end = source.index('if path == "/api/v1/logout":', route_start)
route = source[route_start:route_end]
check(route.index("self.auth_rate(") < route.index("self.app.auth_slots.acquire"))
check(route.index("self.auth_rate(") < route.index("self.app.store.authenticate"))
check("allow_many" in source)
check('"global", "malformed-request"' in source)
check('"global", "device-report"' in source)
check("device_belongs" in source)
check("X-Forwarded-For" in source and "ProxyMetadataError" in source)

print(f"PASS portal_rate_tests checks={checks} "
      "trusted_proxy_atomic_account_device_global_limits=1")
