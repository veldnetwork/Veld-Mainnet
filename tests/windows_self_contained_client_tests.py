#!/usr/bin/env python3
"""Regression checks for the DLL-free Windows client build and layout."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


build = (ROOT / "build/mainnet-v2-windows.sh").read_text(encoding="utf-8")
gui = (ROOT / "src/veld-node-gui.cpp").read_text(encoding="utf-8")
updater = (ROOT / "pkg/veld-update.ps1").read_text(encoding="utf-8")

for archive in ("libc++.a", "libc++abi.a", "libunwind.a", "libleveldb.a"):
    check(archive in build, f"Windows build does not pin {archive}")
check("-nostdlib++" in build, "Windows build may select the shared C++ runtime")
check(
    "release artifact retains a forbidden loose-runtime DLL import" in build,
    "Windows build lacks the post-link DLL-import refusal",
)
check(
    re.search(r"libc\\\+\\\+.*libleveldb.*\\\.dll", build, re.IGNORECASE | re.DOTALL)
    is not None,
    "post-link refusal does not cover libc++ and LevelDB DLL imports",
)

required_match = re.search(
    r"std::unordered_set<std::string> required\s*\{(?P<body>.*?)\};",
    gui,
    re.DOTALL,
)
check(required_match is not None, "GUI signed-package required set is missing")
required = required_match.group("body")
check('"bin/veld-node.exe"' in required, "GUI package does not require the node")
check('"bin/veld-wallet.exe"' in required, "GUI package does not require the wallet")
check(
    '"bin/veld-node-gui.exe"' not in required,
    "GUI package still requires a redundant second GUI executable",
)

node_layout_match = re.search(
    r"\} else \{\s*@\((?P<body>.*?)\)\s*\}\s*\$Node =",
    updater,
    re.DOTALL,
)
check(node_layout_match is not None, "updater Node package layout is missing")
node_layout = node_layout_match.group("body")
for path in (
    "bin/veld-node.exe",
    "bin/veld-wallet.exe",
    "Veld Node.exe",
    "veld-update.ps1",
    "tor-setup.ps1",
    "CHANGES.txt",
):
    check(f"'{path}'" in node_layout, f"updater does not require {path}")
for redundant in ("bin/veld-node-gui.exe", "Start Veld Node.bat"):
    check(f"'{redundant}'" not in node_layout, f"updater still requires {redundant}")

print(f"PASS windows_self_contained_client_tests checks={checks}")
