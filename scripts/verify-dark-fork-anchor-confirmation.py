#!/usr/bin/env python3
"""Verify that only configured outbound anchors suppress blind-mining limits."""

from pathlib import Path
import sys


root = Path(__file__).resolve().parents[1]
tcp = (root / "include/network/tcp.h").read_text(encoding="utf-8")
node = (root / "include/node/node.h").read_text(encoding="utf-8")
errors: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


require(
    "bool configured_outbound_anchors_only = false" in tcp,
    "peer-tip snapshot lacks an explicit trusted-anchor view",
)
require(
    "conn->IsInbound() ||" in tcp
    and "configured_anchors.count(conn->RemoteAddr()) == 0" in tcp,
    "trusted peer-tip view does not require outbound configured anchors",
)
require(
    "SnapshotPeerTips(\n                        "
    "/*configured_outbound_anchors_only=*/true)" in node,
    "mining does not request the trusted-anchor peer-tip view",
)
require(
    "https://explorer.veld.network/api/stats" in node,
    "eclipse oracle does not use the live explorer endpoint",
)
require(
    "https://veld.network/api/stats" not in node,
    "dead eclipse-oracle endpoint remains in node source",
)

if errors:
    for error in errors:
        print(f"DARK-FORK-ANCHOR FAIL: {error}", file=sys.stderr)
    raise SystemExit(1)

print("DARK-FORK-ANCHOR OK: throttle confirmation requires configured outbound anchors;")
print("                     the eclipse oracle uses the live explorer endpoint.")
