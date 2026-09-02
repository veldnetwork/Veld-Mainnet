#!/usr/bin/env python3
"""Focused release-role and validator-oracle regression checks."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


linux = (ROOT / "build/mainnet-v2-linux.sh").read_text(encoding="utf-8")
windows = (ROOT / "build/mainnet-v2-windows.sh").read_text(encoding="utf-8")
verifier = (ROOT / "scripts/verify-pqc-provenance.py").read_text(
    encoding="utf-8"
)

check("operator | fleet" in linux, "Linux usage omits the operator role")
check(
    "operator) source_file=src/veld-miner-portal.py" in linux,
    "Linux operator role is not bound to the reviewed portal source",
)
check(
    "if [[ $role == operator ]]; then\n  definitions=()" in linux,
    "Linux operator falsely claims unused C++ preprocessor definitions",
)
check(
    "veld-public-services.nginx.conf.template" in linux,
    "Linux operator output omits the reviewed reverse-proxy template",
)
check(
    "validator|operator)\n    required_features=(veld-public-mainnet-v2)"
    in linux,
    "Linux validator/operator oracle requires an unrelated feature",
)
check(
    "validator) source_file=src/veld-validator.cpp; binary=veld-validator.exe"
    in windows,
    "Windows standalone validator role is absent",
)
check(
    "keygen || $role == validator || $role == gui" in windows,
    "Windows validator unexpectedly links the node database backend",
)
check(
    "validator)\n      required_features=(veld-public-mainnet-v2)" in windows,
    "Windows validator oracle requires an unrelated reserve feature",
)
check(
    '"operator",' in verifier,
    "PQC precompile/package gate does not recognize the operator role",
)

version = subprocess.run(
    [sys.executable, str(ROOT / "src/veld-miner-portal.py"), "--version"],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
check(version.returncode == 0, "operator --version failed")
check(version.stdout.strip() == "Veld Operator 3.0.0", "wrong operator version")

deployment = subprocess.run(
    [
        sys.executable,
        str(ROOT / "src/veld-miner-portal.py"),
        "--deployment-info",
    ],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
check(deployment.returncode == 0, "operator --deployment-info failed")
info = json.loads(deployment.stdout)
check(info["binary_role"] == "operator-portal", "wrong operator role")
check(info["client_version"] == "3.0.0", "wrong operator release version")
check(
    info["profile_id"] == "veld-public-mainnet-v2",
    "wrong operator network identity",
)
check(not info["snapshot_bootstrap_compiled"], "operator claims snapshot support")
check(not info["public_gettxhistory_compiled"], "operator claims public history")
check(not info["upnp_compiled"], "operator claims UPnP support")

print(f"PASS daybreak_release_controller_oracle_tests checks={checks}")
