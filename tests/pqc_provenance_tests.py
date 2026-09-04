#!/usr/bin/env python3
"""Adversarial tests for the fail-closed PQC provenance gate."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts/verify-pqc-provenance.py"
MANIFEST = Path("vendor/pqc/provenance/PQC_PROVENANCE.tsv")
REBUILD = ROOT / "scripts/rebuild-pqc-wasm.py"
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), "--root", str(root), *extra],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def copy_fixture(destination: Path) -> None:
    with (ROOT / MANIFEST).open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    paths = {row["path"] for row in rows}
    paths.add(MANIFEST.as_posix())
    for rel in paths:
        source = ROOT / rel
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def replace_manifest_hash(root: Path, rel: str) -> None:
    path = root / MANIFEST
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fields = reader.fieldnames
        rows = list(reader)
    assert fields is not None
    actual = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    found = False
    for row in rows:
        if row["path"] == rel:
            row["sha256"] = actual
            found = True
    assert found
    with path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def stage_package(root: Path, destination: Path, role: str) -> None:
    (destination / "licenses").mkdir(parents=True)
    (destination / "provenance/tools").mkdir(parents=True)
    shutil.copyfile(root / "THIRD_PARTY_NOTICES.md",
                    destination / "THIRD_PARTY_NOTICES.md")
    shutil.copyfile(root / "vendor/pqc/mldsa65/LICENSE",
                    destination / "licenses/PQClean-ML-DSA-65-LICENSE")
    shutil.copyfile(root / "vendor/pqc/mlkem768/LICENSE",
                    destination / "licenses/PQClean-ML-KEM-768-LICENSE")
    shutil.copyfile(root / "vendor/pqc/PQCLEAN_VERSION",
                    destination / "provenance/PQCLEAN_VERSION")
    shutil.copytree(root / "vendor/pqc/provenance",
                    destination / "provenance/pqc")
    for name in (
        "generate-mldsa65-nist-kat.py",
        "rebuild-pqc-wasm.py",
        "rebuild-pqc-wasm.sh",
        "verify-pqc-provenance.py",
    ):
        shutil.copyfile(root / "scripts" / name,
                        destination / "provenance/tools" / name)
    if role in {"desktop", "gui"}:
        shutil.copyfile(root / "third_party_licenses/Emscripten-LICENSE.txt",
                        destination / "licenses/Emscripten-LICENSE.txt")


def load_rebuild_module():
    spec = importlib.util.spec_from_file_location("veld_pqc_rebuild", REBUILD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    baseline = run(ROOT)
    check(baseline.returncode == 0, baseline.stderr)
    check("PASS PQC provenance" in baseline.stdout, "missing PASS marker")

    node = run(ROOT, "--release-role", "node")
    check(node.returncode == 0, "non-WASM public role should pass static gate")

    desktop = run(ROOT, "--release-role", "desktop")
    check(desktop.returncode == 0, "desktop release rejected current rebuild proof")
    check("wasm_rebuild=PASS" in desktop.stdout,
          "desktop gate did not report the rebuilt artifact")

    with tempfile.TemporaryDirectory(prefix="veld-pqc-package-test-") as td:
        package_root = Path(td)
        node_package = package_root / "node"
        stage_package(ROOT, node_package, "node")
        check(run(ROOT, "--release-role", "node", "--package-dir",
                  str(node_package)).returncode == 0,
              "valid node third-party package was rejected")
        desktop_package = package_root / "desktop"
        stage_package(ROOT, desktop_package, "desktop")
        check(run(ROOT, "--release-role", "desktop", "--package-dir",
                  str(desktop_package)).returncode == 0,
              "valid desktop third-party package was rejected")
        (desktop_package / "licenses/Emscripten-LICENSE.txt").unlink()
        check(run(ROOT, "--release-role", "desktop", "--package-dir",
                  str(desktop_package)).returncode != 0,
              "desktop package without Emscripten license was accepted")
        target = node_package / "licenses/PQClean-ML-DSA-65-LICENSE"
        target.write_bytes(target.read_bytes() + b"drift")
        check(run(ROOT, "--release-role", "node", "--package-dir",
                  str(node_package)).returncode != 0,
              "package with altered PQClean license was accepted")

    rebuild = load_rebuild_module()
    with tempfile.TemporaryDirectory(prefix="veld-pqc-toolchain-test-") as td:
        emsdk = Path(td)
        (emsdk / ".emscripten").write_bytes(rebuild.DOT_EMSCRIPTEN)
        for rel in rebuild.TREE_ROOTS.values():
            tree = emsdk / Path(*rel.split("/"))
            tree.mkdir(parents=True)
            (tree / "input.bin").write_bytes(rel.encode("ascii"))
        subprocess.run(["git", "init", "-q", str(emsdk)], check=True)
        subprocess.run(["git", "-C", str(emsdk), "config", "user.email",
                        "pqc-test@veld.invalid"], check=True)
        subprocess.run(["git", "-C", str(emsdk), "config", "user.name",
                        "Veld PQC Test"], check=True)
        subprocess.run(["git", "-C", str(emsdk), "add", "."], check=True)
        subprocess.run(["git", "-C", str(emsdk), "commit", "-q", "-m", "fixture"],
                       check=True)
        lock = rebuild.toolchain_measurements(emsdk)
        check(rebuild.verify_toolchain(emsdk, lock) == lock,
              "clean pinned toolchain fixture was rejected")
        changed = emsdk / "upstream/bin/input.bin"
        changed.write_bytes(b"changed executable input")
        subprocess.run(["git", "-C", str(emsdk), "add", "."], check=True)
        subprocess.run(["git", "-C", str(emsdk), "commit", "-q", "-m", "drift"],
                       check=True)
        try:
            rebuild.verify_toolchain(emsdk, lock)
            tree_rejected = False
        except RuntimeError:
            tree_rejected = True
        check(tree_rejected, "clean but raw-different toolchain tree was accepted")
        (emsdk / ".emscripten").write_text("LLVM_ROOT = 'attacker'\n",
                                           encoding="utf-8", newline="\n")
        subprocess.run(["git", "-C", str(emsdk), "add", "."], check=True)
        subprocess.run(["git", "-C", str(emsdk), "commit", "-q", "-m", "config drift"],
                       check=True)
        try:
            rebuild.verify_toolchain(emsdk, lock)
            config_rejected = False
        except RuntimeError:
            config_rejected = True
        check(config_rejected, "attacker-selected .emscripten content was accepted")

    with tempfile.TemporaryDirectory(prefix="veld-pqc-provenance-test-") as td:
        fixture = Path(td)
        copy_fixture(fixture)

        target = fixture / "vendor/pqc/mldsa65/sign.c"
        original = target.read_bytes()
        target.write_bytes(original + b"\n/* drift */\n")
        check(run(fixture).returncode != 0, "compiled C drift was accepted")
        target.write_bytes(original)

        target = fixture / "include/network/dilithium_wasm_js.h"
        original = target.read_bytes()
        target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        check(run(fixture).returncode != 0, "embedded-header drift was accepted")
        target.write_bytes(original)

        target = fixture / "include/crypto/mldsa65_nist_kat.h"
        original = target.read_bytes()
        target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        check(run(fixture).returncode != 0, "compiled ML-DSA KAT drift was accepted")
        target.write_bytes(original)

        target = fixture / "include/crypto/vendored.h"
        original = target.read_bytes()
        target.write_bytes(original + b"\n/* forged reviewed source */\n")
        replace_manifest_hash(fixture, "include/crypto/vendored.h")
        semantic_pin = run(fixture)
        check(semantic_pin.returncode != 0,
              "vendored.h drift with forged manifest hash was accepted")
        check("raw vendored.h SHA-256" in semantic_pin.stderr,
              "vendored.h drift failed for the wrong reason")
        target.write_bytes(original)
        replace_manifest_hash(fixture, "include/crypto/vendored.h")

        target = fixture / "vendor/pqc/dilithium_wasm.js"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        check(run(fixture).returncode != 0, "canonical JS drift was accepted")
        target.write_bytes(original)

        untracked = fixture / "vendor/pqc/mldsa65/unmanifested.h"
        untracked.write_text("#error unmanifested\n", encoding="utf-8")
        check(run(fixture).returncode != 0, "unmanifested PQC header was accepted")
        untracked.unlink()

        target = fixture / "vendor/pqc/provenance/release-c-sources.txt"
        original = target.read_bytes()
        text = original.decode("utf-8")
        text = text.replace(
            "vendor/pqc/fips202.c\nvendor/pqc/randombytes.c",
            "vendor/pqc/randombytes.c\nvendor/pqc/fips202.c",
        )
        target.write_text(text, encoding="utf-8", newline="\n")
        check(run(fixture).returncode != 0, "compiled source-list drift was accepted")
        target.write_bytes(original)

        target = fixture / "build/mainnet-v2-windows.sh"
        original = target.read_bytes()
        target.write_bytes(original + b"\n# bypass\n")
        check(run(fixture).returncode != 0, "release-controller drift was accepted")
        target.write_bytes(original)

        target = fixture / "scripts/verify-pqc-provenance.py"
        original = target.read_bytes()
        target.write_bytes(original + b"\n# verifier drift\n")
        check(run(fixture).returncode != 0, "verifier drift was accepted")
        target.write_bytes(original)

        attestation_rel = "vendor/pqc/provenance/wasm-rebuild-attestation.tsv"
        target = fixture / attestation_rel
        text = target.read_text(encoding="utf-8")
        text = text.replace(
            next(line for line in text.splitlines() if line.startswith("input_digest\t")),
            "input_digest\t" + "0" * 64,
        )
        target.write_text(text, encoding="utf-8", newline="\n")
        replace_manifest_hash(fixture, attestation_rel)
        forged = run(fixture, "--release-role", "desktop")
        check(forged.returncode != 0, "forged PASS rebuild attestation was accepted")
        check("input digest is stale" in forged.stderr,
              "forged attestation failed for the wrong reason")

    print(f"PASS PQC provenance checks={checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
