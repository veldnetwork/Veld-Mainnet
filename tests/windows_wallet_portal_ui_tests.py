#!/usr/bin/env python3
"""Regression checks for the Windows wallet link and mobile portal shell."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = (ROOT / "src" / "veld-node-gui.cpp").read_text(encoding="utf-8")
PORTAL = (ROOT / "src" / "veld-miner-portal.py").read_text(encoding="utf-8")
WALLET = (ROOT / "include" / "network" / "ui_desktop.h").read_text(encoding="utf-8")
EXPLORER = (ROOT / "include" / "network" / "explorer.h").read_text(encoding="utf-8")


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

require("const CACHE='veld-portal-shell-v18'" in PORTAL, "portal cache version")
require('id="mobile-nav"' in PORTAL, "portal needs a dedicated mobile navbar")
require('$("mobile-nav").hidden=!d' in PORTAL,
        "unpaired portal must not expose inactive navigation")
require(".side{display:none!important}" in PORTAL, "desktop sidebar must be hidden on mobile")
require(
    'document.querySelectorAll("#nav button,#mobile-nav button")' in PORTAL,
    "desktop and mobile navigation must share page state",
)
for required in (
    "#mobile-nav{display:flex!important;position:fixed;bottom:0",
    "height:68px;min-height:68px;max-height:68px",
    "#mobile-nav{display:none}#mobile-nav[hidden]{display:none!important}",
    ".app.unpaired .main{padding-bottom:20px!important}",
):
    require(required in PORTAL, f"portal mobile shell is missing {required}")

for required in (
    'L"New pair code"',
    'portal_pair_reset_requested_.store(true)',
    'L"/api/v1/device/reset-pairing"',
    'remote_trust_ = {}',
):
    require(required in GUI, f"Windows client pairing reset is missing {required}")
require('def reset_pairing(self, token: str)' in PORTAL,
        "portal does not implement authenticated device re-pairing")
require('path == "/api/v1/device/reset-pairing"' in PORTAL,
        "portal pairing reset route is missing")

for surface_name, surface in (
    ("wallet", WALLET),
    ("explorer", EXPLORER),
    ("portal", PORTAL),
):
    for forbidden in ("testnet", "regtest"):
        require(
            forbidden not in surface.lower(),
            f"{surface_name} public source contains {forbidden}",
        )

require(
    'class="ar stake" data-act-click="h9c6994df" type="button" disabled '
    'aria-disabled="true"' in WALLET,
    "wallet quick stake control must start locked",
)
require(
    'data-act-click="h2e4ed19f" disabled aria-disabled="true"' in WALLET,
    "wallet stake submission must start locked",
)
require(
    "function setStakingActivationUi(active, supply, threshold, known)" in WALLET,
    "wallet must centrally apply the live activation state",
)
require(
    "button.disabled = locked" in WALLET,
    "wallet activation state must control both stake buttons",
)
do_stake = WALLET[WALLET.index("function doStake() {"):
                  WALLET.index("function _doStakeContinue(")]
require(
    "if (!_veldStakingActivation.active)" in do_stake,
    "direct stake submission must fail closed before activation",
)
require(
    do_stake.index("if (!_veldStakingActivation.active)") <
    do_stake.index("if (!__opLock('stake'"),
    "activation rejection must precede transaction preparation",
)
require(
    "setStakingActivationUi(false, 0, 10000, false)" in WALLET,
    "staking controls must remain locked when activation RPC is unavailable",
)
require(
    "d.current_supply_veld" in WALLET and "d.activation_supply_veld" in WALLET,
    "staking lock must use the live consensus supply and threshold",
)

print("PASS windows_wallet_portal_ui_tests checks=32")
