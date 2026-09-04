#!/usr/bin/env python3
"""Static regression gates for public mainnet web and wallet surfaces."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLORER = (ROOT / "include/network/explorer.h").read_text(encoding="utf-8")
WALLET = (ROOT / "include/network/ui_desktop.h").read_text(encoding="utf-8")
HOME = (ROOT / "website/index.html").read_text(encoding="utf-8")
SW = (ROOT / "resources/explorer-sw-v2.js").read_text(encoding="utf-8")
ROUTE = (ROOT / "resources/explorer-route-context-v1.js").read_text(encoding="utf-8")
NODE = (ROOT / "src/veld-node.cpp").read_text(encoding="utf-8")
CLI = (ROOT / "include/wallet/cli.h").read_text(encoding="utf-8")
PORTAL = (ROOT / "src/veld-miner-portal.py").read_text(encoding="utf-8")
PROXY = (ROOT / "pkg/reverse-proxy/veld-public-services.nginx.conf.template").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


for public_surface in (EXPLORER, WALLET, HOME):
    lowered = public_surface.lower()
    require("every transaction is signed with ml-dsa-65" not in lowered,
            "overbroad transaction-signature claim returned")
    require("veld is a post-quantum" not in lowered,
            "overbroad post-quantum product claim returned")

require("Native VELD transaction and finality signatures use ML-DSA-65" in EXPLORER,
        "explorer cryptographic boundary is missing")
require("160-bit HASH160 key commitments" in EXPLORER,
        "explorer HASH160 qualification is missing")
require("Bitcoin Taproot" in EXPLORER,
        "explorer btcVELD dependency is missing")

require("50% to the miner and 50% to the vault" in EXPLORER,
        "explorer pre-activation split is missing")
require("Before activation the co-mining-pool share is zero" in EXPLORER,
        "explorer co-mining activation boundary is missing")
require("Before activation the validator-pool share is zero" in EXPLORER,
        "explorer validator activation boundary is missing")
require("ordinary_vault_share = staking_active ? 0.20 : 0.50" in EXPLORER,
        "vault projection is not phase-aware")
require("std::setprecision(2) << bal" in EXPLORER,
        "rich-list balances are not rendered with two decimal places")

require("id=\"sk-stake-btn\"" in WALLET and
        "id=\"sk-stake-btn\" data-act-click=\"h2e4ed19f\" disabled" in WALLET,
        "stake submission is not disabled before activation state loads")
require("window._veldStakingActive !== true" in WALLET,
        "stake submission lacks a client-side activation gate")
require("si.min_stake_veld || 1000" in WALLET,
        "mainnet minimum-stake fallback is not 1,000 VELD")
require("stakingActive ? 0.50 : 1.00" not in WALLET,
        "wallet still reports a 100% pre-activation miner share")

require("Before staking activates, ordinary blocks split 50%" in HOME,
        "homepage pre-activation split is missing")
require("Post-activation ordinary block split" in HOME,
        "homepage does not label the four-way split boundary")
require("testnet" not in HOME.lower() and "test net" not in HOME.lower(),
        "homepage exposes a test-network reference")

require("caches.open(" not in SW and "cache.put(" not in SW,
        "explorer service worker must not cache HTML documents")
require("fetch(event.request, {cache: 'no-store'})" in SW,
        "explorer navigation is not network-only")
require("20260904-network-only" in EXPLORER,
        "explorer service-worker registration was not advanced")
require("renderConsensusPhase" in ROUTE and "fetch('/api/stats'" in ROUTE,
        "deployed explorer presentation is not bound to live consensus phase")
require("refreshObservedHashrate" in ROUTE and
        "calculateExpectedHashes" in ROUTE and
        "Hashrate (10-block estimate)" in ROUTE,
        "explorer hashrate is not derived from canonical work and recent blocks")
require("testnet" not in ROUTE.lower() and "test net" not in ROUTE.lower(),
        "explorer public runtime asset exposes a test-network reference")
require("Veld 3.0.0 public release" not in NODE and
        "Veld 3.0.0 public release" not in CLI,
        "stale launch-version wording returned to current user-facing output")
require("https://explorer.veld.network" in CLI,
        "command-line wallet history guidance lacks the public explorer link")
require(all("testnet" not in surface.lower() and "test net" not in surface.lower()
            for surface in (EXPLORER, WALLET, HOME, ROUTE, SW, PORTAL, PROXY)),
        "a production public surface exposes a test-network reference")

print("public mainnet surface checks: PASS (30 assertions)")
