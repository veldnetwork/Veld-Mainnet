"""Prove both caller checks run, tolerate comments and reject controlled defects."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
wallet = (ROOT / "include/network/ui_desktop.h").read_text(encoding="utf-8")
env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
checks = 0
with tempfile.TemporaryDirectory(prefix="veld-caller-checks-") as directory:
    fixture = Path(directory) / "wallet.h"
    def run(source, expected, caller=None):
        global checks
        fixture.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "tests/security_scan_closure_wiring_tests.py"),
             "--wallet-source", str(fixture)], env=env, capture_output=True, text=True, timeout=40)
        assert (result.returncode == 0) == expected, result.stdout + result.stderr
        if expected:
            for name in ("autoConsolidateRun", "doConsolidateUtxos"):
                assert "CHECKED: " + name in result.stdout, result.stdout
        elif caller:
            assert caller in result.stderr, result.stdout + result.stderr
        checks += 1
    run(wallet, True)
    run(wallet.replace("// An idle page also checks every 30 minutes, subject to the same explicit opt-in.",
                       "/* Renamed surrounding comment: } function ignored() { */"), True)
    # Braces in nested syntax and indented closing braces must not end a caller.
    run(wallet.replace("  var signingBudget = _veldAutomaticConsolidationBudget();",
        "  /* } nested comment { */\n"
        "  var parserFixture = {text: '} {', regex: /[{}]/, template: `value ${1 + 2}`};\n"
        "  var signingBudget = _veldAutomaticConsolidationBudget();")
        .replace("\n}\n\n// An idle page", "\n  }\n\n// An idle page"), True)
    for caller, budget in (("autoConsolidateRun", "_veldAutomaticConsolidationBudget()"),
                           ("doConsolidateUtxos", "_veldConsolidationBudget(64)")):
        begin = wallet.index("function " + caller)
        at = wallet.index(budget, begin)
        run(wallet[:at] + "null" + wallet[at + len(budget):], False, caller)
        at = wallet.index("verified_consolidation_inputs", begin)
        run(wallet[:at] + "inputs_consolidated" + wallet[at + len("verified_consolidation_inputs"):], False, caller)
        run(wallet.replace("function " + caller + "(", "function missingCaller("), False, caller)
print("PASS: " + str(checks) + " caller extraction and mutation controls")
