#!/usr/bin/env python3
"""Run the portable source and web regression suites from any working directory."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    "source": [
        "tests/portal_mobile_nav_tests.py",
        "tests/topology_advertised_roles_tests.py",
        "tests/release_controller_oracle_tests.py",
        "tests/windows_node_gui_scroll_tests.py",
        "tests/windows_node_keyfile_interop_tests.py",
        "tests/windows_self_contained_client_tests.py",
        "tests/windows_snapshot_update_eligibility_tests.py",
        "tests/windows_wallet_portal_ui_tests.py",
    ],
    "web": [
        "tests/network_display_refresh_tests.js",
        "tests/portal_network_status_tests.js",
        "tests/portal_pair_machine_tests.js",
        "tests/wallet_auto_consolidation_tests.js",
        "tests/wallet_governance_activity_tests.js",
        "tests/wallet_history_pagination_tests.js",
        "tests/wallet_stake_navigation_tests.js",
        "tests/wallet_transaction_policy_tests.js",
        "tests/web_freshness_tests.js",
    ],
    "provenance": [
        "scripts/verify-pqc-provenance.py",
        "tests/pqc_provenance_tests.py",
        "tests/pqc_wasm_smoke.js",
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=[*SUITES, "all"], default="all")
    parser.add_argument("--list", action="store_true", help="list checks without running them")
    args = parser.parse_args()
    paths = [path for name, paths in SUITES.items()
             if args.suite in (name, "all") for path in paths]
    if args.list:
        print("\n".join(paths))
        return 0
    node = shutil.which("node")
    if any(path.endswith(".js") for path in paths) and not node:
        parser.error("Node.js is required for the selected suite")
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    failures = []
    for path in paths:
        command = ([node] if path.endswith(".js") else [sys.executable, "-X", "utf8"])
        command.append(str(ROOT / path))
        if path == "tests/pqc_wasm_smoke.js":
            command.append(str(ROOT / "vendor/pqc/dilithium_wasm.js"))
        print(f"\nRunning {path}", flush=True)
        try:
            result = subprocess.run(command, cwd=ROOT,
                                    env=env, timeout=180, check=False)
            if result.returncode:
                failures.append(path)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            failures.append(path)
    print(f"\n{len(paths) - len(failures)}/{len(paths)} checks passed")
    if failures:
        print("Failed checks:\n" + "\n".join(failures), file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
