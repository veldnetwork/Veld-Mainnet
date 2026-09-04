#!/usr/bin/env python3
"""Positive and negative tests for the public source hygiene gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-public-source-hygiene.py"
SPEC = importlib.util.spec_from_file_location("source_hygiene", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


check(not CHECKER.scan(ROOT, CHECKER.tracked_paths(ROOT)),
      "current tracked source must pass the hygiene gate")

with tempfile.TemporaryDirectory(prefix="veld-source-hygiene-") as temporary:
    root = Path(temporary)
    clean = root / "clean.cpp"
    clean.write_text("// Reviewed networking boundary.\n", encoding="utf-8")
    check(not CHECKER.scan(root, [PurePosixPath(clean.name)]),
          "professional source text was rejected")

    prohibited = "day" + "break"
    branded_path = root / f"{prohibited}_test.cpp"
    branded_path.write_text("int main() { return 0; }\n", encoding="utf-8")
    check(bool(CHECKER.scan(root, [PurePosixPath(branded_path.name)])),
          "internal branding in a tracked path was accepted")

    branded_content = root / "content.cpp"
    branded_content.write_text(f"// {prohibited}\n", encoding="utf-8")
    check(bool(CHECKER.scan(root, [PurePosixPath(branded_content.name)])),
          "internal branding in tracked text was accepted")

    historical = root / "LAUNCH_EQUIVALENCE.tsv"
    historical.write_text(f"tests/{prohibited}_legacy.cpp\n", encoding="utf-8")
    check(not CHECKER.scan(root, [PurePosixPath(historical.name)]),
          "immutable historical evidence was not allowlisted narrowly")

print(f"PASS public_source_hygiene_tests checks={checks}")
