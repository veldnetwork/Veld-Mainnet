#!/usr/bin/env python3
"""Source gate for release-bound fleet-clock-anchor provenance.

The authoritative clock set may be populated by the signed exact-IP fleet
inventory or the strict operator configuration path. Ordinary discovery seeds
and ``--connect`` peers cannot acquire clock authority.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


def method_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise ValueError(f"missing method signature: {signature}")
    brace = source.find("{", start + len(signature))
    if brace < 0:
        raise ValueError(f"missing method body: {signature}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise ValueError(f"unterminated method body: {signature}")


parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
args = parser.parse_args()
root = args.root.resolve()
errors: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


node_header = (root / "include/node/node.h").read_text(encoding="utf-8")
tcp_header = (root / "include/network/tcp.h").read_text(encoding="utf-8")
seeder_header = (root / "include/network/seeder.h").read_text(encoding="utf-8")

try:
    ordinary = method_body(
        node_header,
        "bool ConnectTo(const std::string& host, uint16_t port)",
    )
    require(
        "/*fleet_anchor=*/false" in ordinary,
        "VeldNode::ConnectTo does not explicitly deny fleet-anchor authority",
    )
    require(
        "/*fleet_anchor=*/true" not in ordinary,
        "ordinary VeldNode::ConnectTo still grants fleet-anchor authority",
    )

    explicit = method_body(
        node_header,
        "bool AddFleetAnchorIp(const std::string& ip)",
    )
    for marker, label in (
        ("IsCanonicalIPv4Literal(ip)", "canonical exact-IP validation"),
        ("config_.port", "network P2P-port dial"),
        ("/*explicitly_trusted=*/true", "explicit trust"),
        ("/*fleet_anchor=*/true", "explicit fleet-anchor dial"),
    ):
        require(marker in explicit, f"VeldNode::AddFleetAnchorIp lacks {label}")
except ValueError as exc:
    errors.append(str(exc))

for marker, label in (
    ("static bool IsCanonicalIPv4Literal", "canonical IPv4 policy"),
    ("if (fleet_anchor &&", "fleet-anchor connection guard"),
    ("!IsCanonicalIPv4Literal(host)", "hostname/alternate-IP rejection"),
    ("if (!AddFleetAnchorIp(host)) return false;", "configured membership insertion"),
):
    require(marker in tcp_header, f"NodeServer lacks {label}")

for marker, label in (
    ("GetHardcodedFleetAnchorIps", "signed fleet inventory"),
    ('"108.61.119.29"', "Fleet 01 canonical address"),
    ('"5.78.107.166"', "Fleet 02 canonical address"),
    ('"5.78.97.56"', "Fleet 03 canonical address"),
    ('"5.78.127.51"', "Fleet 04 canonical address"),
):
    require(marker in seeder_header, f"seeder lacks {label}")

sources = (
    "src/veld-node.cpp",
    "src/veld-desktop.cpp",
)
for relative in sources:
    source = (root / relative).read_text(encoding="utf-8")
    main = source.find("int main(int argc, char* argv[])")
    require(main >= 0, f"{relative} has no canonical main entry")
    if main < 0:
        continue
    scoped = source[main:]
    for marker, label in (
        ('"--fleet-anchor"', "repeatable CLI parser"),
        ("--fleet-anchor <IPv4>", "help text"),
        ("VELD_FLEET_ANCHOR_IPS", "environment parser/help"),
        ("AppendFleetAnchorEnvironment", "strict environment grammar"),
        ("NodeServer::IsCanonicalIPv4Literal", "exact-IP validation"),
        ("node.AddFleetAnchorIp(ip)", "explicit registration/dial"),
        ("Seed node ", "stable public seed label"),
        ("temporarily unavailable; retrying", "visible retry status"),
        ("DiagVerbose().load()", "diagnostic endpoint visibility gate"),
        ("(tick % 30) == 0", "periodic idempotent redial"),
    ):
        require(marker in scoped, f"{relative} lacks fleet-anchor {label}")
    require(
        "GetHardcodedFleetAnchorIps" in scoped,
        f"{relative} does not install the release-bound fleet inventory",
    )
    require(
        "contains an empty entry" in source,
        f"{relative} lacks fleet-anchor empty environment-entry rejection",
    )

    start_at = scoped.find("node.Start();")
    add_at = scoped.find("node.AddFleetAnchorIp(ip)", start_at + 1)
    connect_at = scoped.find("node.ConnectTo(", start_at + 1)
    require(
        start_at >= 0 and add_at > start_at,
        f"{relative} does not register/dial anchors after node.Start",
    )
    require(
        connect_at < 0 or (add_at >= 0 and add_at < connect_at),
        f"{relative} dials ordinary seeds/--connect before configured anchors",
    )
    require(
        scoped.count("node.AddFleetAnchorIp(ip)") == 2,
        f"{relative} must have exactly one initial and one retry anchor dial",
    )
    require(
        "/*fleet_anchor=*/true" not in scoped,
        f"{relative} bypasses the exact-IP AddFleetAnchorIp API",
    )
    require(
        "outbound retry failed for " not in scoped
        and "registered and dialed outbound" not in scoped,
        f"{relative} exposes raw anchor endpoints in ordinary status text",
    )

require(
    "#ifdef VELD_FLEET_NO_MINE" in node_header
    and "StartMining() refused" in node_header
    and "MineBlocks disabled" in node_header,
    "VELD_FLEET_NO_MINE compile-time mining refusal was weakened",
)

if errors:
    for error in errors:
        print("FLEET-ANCHOR-CLI FAIL:", error, file=sys.stderr)
    raise SystemExit(1)

print("FLEET-ANCHOR-CLI OK: signed or operator-supplied exact-IP anchors are authoritative;")
print("                     ordinary discovery and --connect remain non-authoritative.")
