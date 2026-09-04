#!/usr/bin/env python3
"""Structural interlock for explorer proxy identity and pre-route budgets."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
EXPLORER = (ROOT / "include/network/explorer.h").read_text(encoding="utf-8")
PROXY = (ROOT / "include/network/trusted_proxy.h").read_text(encoding="utf-8")
TEMPLATE = (
    ROOT / "pkg/reverse-proxy/veld-public-services.nginx.conf.template"
).read_text(encoding="utf-8")

checks = 0


def check(value: bool) -> None:
    global checks
    checks += 1
    if not value:
        raise AssertionError(f"check {checks} failed")


def has_constant(name: str, value: int) -> bool:
    pattern = rf"static\s+constexpr\s+[^;=]+\s+{re.escape(name)}\s*=\s*{value}\s*;"
    return re.search(pattern, EXPLORER) is not None


check('ip == "127.0.0.1" || ip == "::1"' not in EXPLORER)
check("ExplorerTakeRateToken_" not in EXPLORER)
check("net::trusted_proxy::Resolve(" in EXPLORER)
check(EXPLORER.index("net::trusted_proxy::Resolve(") <
      EXPLORER.index("auto res = Route(req);"))
check(EXPLORER.index("BeginExplorerAdmission_(proxy.identity") <
      EXPLORER.index("auto res = Route(req);"))
check(has_constant("EXPLORER_PER_CLIENT_CAP", 60))
check(has_constant("EXPLORER_RATE_MAP_MAX", 10000))
check(has_constant("EXPLORER_MEMORY_UNITS_MAX", 128))
check(has_constant("EXPLORER_WORK_UNITS_MAX", 64))
check(has_constant("EXPLORER_HISTORY_INFLIGHT_MAX", 4))
check('{identity, "history", 1, 8, 60}' in EXPLORER)
check('{"global", "history", 1, 60, 60}' in EXPLORER)
check('{"global", "requests", 1, 6000, 60}' in EXPLORER)
check('"global", "route:" + route' in EXPLORER)
check('"global", "memory-window"' in EXPLORER)
check('"global", "work-window"' in EXPLORER)
check('"invalid-http"' in EXPLORER)
check('"invalid-proxy"' in EXPLORER)
check("explorer_rate_slots_.size() >= EXPLORER_RATE_MAP_MAX / 2" in EXPLORER)
check("now_s >= expiry" in EXPLORER)
check("ambiguous_headers = true" in EXPLORER)
check("req.headers.emplace" in EXPLORER)
check('headers.count("x-forwarded-for")' in PROXY)
check('headers.count("x-real-ip")' in PROXY)
check("ConstantTimeEqual" in PROXY)
check("IPv4-mapped IPv6" in PROXY)
check("channel::secure_file::Read" in PROXY)
check('std::filesystem::path(cache_dir_) / "explorer-proxy.conf"' in EXPLORER)
check('version != "VELD_EXPLORER_PROXY_V1"' in EXPLORER)
check("token_path.is_absolute()" in EXPLORER)
check("X-Veld-Client-IP $remote_addr" in TEMPLATE)
check('proxy_set_header X-Forwarded-For ""' in TEMPLATE)
check("limit_req_zone" in TEMPLATE)
check("limit_conn_zone" in TEMPLATE)
check("client_max_body_size 256k" in TEMPLATE)

print(f"PASS explorer_proxy_admission_tests checks={checks} "
      "pre_route_identity_history_memory_work_interlocks=1")
