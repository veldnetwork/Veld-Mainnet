#!/usr/bin/env python3
"""Regression checks for the Windows wallet link and mobile portal shell."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = (ROOT / "src" / "veld-node-gui.cpp").read_text(encoding="utf-8")
PORTAL = (ROOT / "src" / "veld-miner-portal.py").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


wallet_start = GUI.index("    void OpenTrustedWallet() {")
wallet_end = GUI.index("\n    void ToggleNode()", wallet_start)
wallet_handler = GUI[wallet_start:wallet_end]

require(
    'L"https://wallet.veld.network/"' in wallet_handler,
    "Wallet button must open the canonical HTTPS wallet",
)
for forbidden in (
    "127.0.0.1",
    "--rpcurl",
    "--uiport",
    "CreateProcessW",
    "VELD_LOCAL_SIGNER_TOKEN",
):
    require(
        forbidden not in wallet_handler,
        f"Wallet button must not use the retired local RPC launch path: {forbidden}",
    )

require("const CACHE='veld-portal-shell-v9'" in PORTAL, "portal cache version")
require("wallet PWA's proven architecture" in PORTAL, "mobile shell marker")
require('id="mobile-nav"' in PORTAL, "portal needs a dedicated mobile navbar")
require(".side{display:none!important}" in PORTAL, "desktop sidebar must be hidden on mobile")
require(
    'document.querySelectorAll("#nav button,#mobile-nav button")' in PORTAL,
    "desktop and mobile navigation must share page state",
)
for required in (
    "height:auto!important",
    "min-height:100dvh!important",
    "position:fixed!important",
    "bottom:0!important",
    "height:68px!important",
    "will-change:transform!important",
    "overflow:visible!important",
):
    require(required in PORTAL, f"portal mobile shell is missing {required}")

print("PASS windows_wallet_portal_ui_tests checks=18")
