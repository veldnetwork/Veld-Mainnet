#!/usr/bin/env python3
"""Regression checks for the public-mainnet liquidity snapshot publisher."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "pkg" / "reverse-proxy" / "veld-liquidity-agg.sh").read_text(
    encoding="utf-8"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for required in (
    'network.get("profile_id") != "veld-public-mainnet-v2"',
    're.fullmatch(r"/Veld:3\\.[0-9]+\\.[0-9]+/", network["subversion"])',
    'network.get("genesis_fingerprint") !=',
    'network.get("disposable") is not False',
    'network.get("external_value") is not True',
    'peg.get("tip") != height',
    'processed_height != height',
    'processed_tip != tip',
):
    require(required in SCRIPT, f"missing production liquidity gate: {required}")

require('/Veld:3.0.0/' not in SCRIPT, "publisher must not pin an obsolete patch release")
require("testnet" not in SCRIPT.lower(), "publisher must not reference a test network")
require("regtest" not in SCRIPT.lower(), "publisher must not reference a test network")
require("unset T" in SCRIPT, "RPC bearer token must be cleared before publication")
require("os.O_NOFOLLOW" in SCRIPT, "publication verification must refuse symlinks")

print("PASS liquidity_aggregator_mainnet_tests checks=13")
