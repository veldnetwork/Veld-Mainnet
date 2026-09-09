#!/usr/bin/env python3
"""Reject mixed release versions and ambiguous deployment reports."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/verify-release-version.py"
spec = importlib.util.spec_from_file_location("release_version", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
header = ('inline constexpr const char* CLIENT_VERSION = "9.8.7";\n'
          'inline constexpr const char* CLIENT_USER_AGENT = "/Veld:9.8.7/";\n')
checks = 0
for prefix in ("", "VELD_DEPLOYMENT_INFO_V1_JSON "):
    assert module.verify(header, prefix + '{"client_version":"9.8.7"}') == "9.8.7"
    checks += 1
for candidate, report in (
        (header, '{"client_version":"3.1.1"}'),
        (header, '{}'),
        (header, '[]'),
        (header, '{"client_version":"9.8.7","client_version":"9.8.7"}'),
        (header, '{"client_version":"9.8.7"}\n{"client_version":"9.8.7"}'),
        (header, 'warning\n{"client_version":"9.8.7"}'),
        (header.replace('/Veld:9.8.7/', '/Veld:9.8.6/'), '{"client_version":"9.8.7"}'),
        (header + header, '{"client_version":"9.8.7"}')):
    try:
        module.verify(candidate, report)
    except ValueError:
        checks += 1
    else:
        raise AssertionError("inconsistent release identity was accepted")
with tempfile.TemporaryDirectory(prefix="veld-version-test-") as directory:
    root = Path(directory)
    (root / "include/core").mkdir(parents=True)
    (root / "include/core/version.h").write_text(header, encoding="utf-8")
    deployment = root / "deployment.txt"
    for version, expected in (("9.8.7", 0), ("3.1.1", 1)):
        deployment.write_text('{"client_version":"' + version + '"}', encoding="utf-8")
        result = subprocess.run([sys.executable, str(path), "--root", str(root),
                                 "--deployment-info", str(deployment)],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == expected, result.stdout + result.stderr
        checks += 1
for name in ("mainnet-v2-linux.sh", "mainnet-v2-windows.sh"):
    controller = (ROOT / "build" / name).read_text(encoding="utf-8")
    assert 'scripts/verify-release-version.py' in controller
    assert '"client_version":"3.1.1"' not in controller
    checks += 1
print(f"PASS release_version_tests checks={checks}")
