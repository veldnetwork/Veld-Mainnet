#!/usr/bin/env python3
"""Fail-closed raw-byte provenance verification for Veld's PQC inputs.

The release controllers invoke this program before compilation and again
before packaging.  Normal verification is offline: the checked-in manifest
contains both local and upstream raw SHA-256 values.  Maintainers can also
provide an exact PQClean checkout with --upstream-dir to prove that unpatched
files are byte-identical and that each recorded patch reconstructs the local
file.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile


PQClean_REVISION = "202a8f96315f9ed219387a50f7e40d04af037ea8"
EMSDK_IMAGE = (
    "emscripten/emsdk@"
    "sha256:90b757eb11fa9a0e3ce4d2d9f76d932a56018e4accc37b5a28b2783751e60eb7"
)
EMCC_VERSION = "4.0.10"
EMSDK_REVISION = "62a853cd3b3134398ce85cde8bb5cbb2ef0194cb"
TOOLCHAIN_IDENTITY = (
    "emsdk-windows-x86_64-4.0.10-releases-"
    "8103ffedfb0c42d231c6af6859a5a1a832260b43"
)

MANIFEST_REL = PurePosixPath("vendor/pqc/provenance/PQC_PROVENANCE.tsv")
SOURCE_LIST_REL = PurePosixPath("vendor/pqc/provenance/release-c-sources.txt")
ATTESTATION_REL = PurePosixPath(
    "vendor/pqc/provenance/wasm-rebuild-attestation.tsv"
)
CANONICAL_JS_REL = PurePosixPath("vendor/pqc/dilithium_wasm.js")
EMBEDDED_HEADER_REL = PurePosixPath("include/network/dilithium_wasm_js.h")
KAT_HEADER_REL = PurePosixPath("include/crypto/mldsa65_nist_kat.h")
KAT_GENERATOR_REL = PurePosixPath("scripts/generate-mldsa65-nist-kat.py")
KAT_META_PATH = "crypto_sign/ml-dsa-65/META.yml"
KAT_META_SHA256 = "e83150131384d5e43a2a59baedcef96c48f5bbf4dce9377094f9bdc3ed12f7d6"
KAT_RESPONSE_SHA256 = "7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072"
VENDORED_REL = PurePosixPath("include/crypto/vendored.h")
VENDORED_PIN_RELS = (
    PurePosixPath("include/crypto/vendored_pin.h"),
    PurePosixPath("include/crypto/vendored_pin_expected.h"),
    PurePosixPath("include/crypto/vendored_pin_history.h"),
)

COMPILED_C = (
    "vendor/pqc/fips202.c",
    "vendor/pqc/randombytes.c",
    "vendor/pqc/mldsa65/ntt.c",
    "vendor/pqc/mldsa65/packing.c",
    "vendor/pqc/mldsa65/poly.c",
    "vendor/pqc/mldsa65/polyvec.c",
    "vendor/pqc/mldsa65/reduce.c",
    "vendor/pqc/mldsa65/rounding.c",
    "vendor/pqc/mldsa65/sign.c",
    "vendor/pqc/mldsa65/symmetric-shake.c",
    "vendor/pqc/mldsa65/veld_seedgen.c",
)

FIXED_COVERAGE = {
    ".gitattributes",
    ".gitignore",
    "THIRD_PARTY_NOTICES.md",
    "build/mainnet-v2-linux.sh",
    "build/mainnet-v2-windows.sh",
    "include/crypto/mldsa65_nist_kat.h",
    "include/crypto/vendored.h",
    "include/crypto/vendored_pin.h",
    "include/crypto/vendored_pin_expected.h",
    "include/crypto/vendored_pin_history.h",
    "include/network/dilithium_wasm_js.h",
    "scripts/generate-mldsa65-nist-kat.py",
    "scripts/rebuild-pqc-wasm.py",
    "scripts/rebuild-pqc-wasm.sh",
    "scripts/verify-pqc-provenance.py",
    "tests/daybreak_pqc_provenance_tests.py",
    "tests/pqc_wasm_smoke.js",
    "third_party_licenses/Emscripten-LICENSE.txt",
}

PATCHES = {
    "vendor/pqc/mldsa65/sign.c": (
        "vendor/pqc/provenance/vendor-patches/"
        "0001-mldsa65-sign-constant-time.patch"
    ),
    "vendor/pqc/randombytes.c": (
        "vendor/pqc/provenance/vendor-patches/"
        "0002-randombytes-fail-closed-webcrypto.patch"
    ),
    "vendor/pqc/mldsa65/veld_seedgen.c": (
        "vendor/pqc/provenance/vendor-patches/"
        "0003-mldsa65-veld-seedgen.patch"
    ),
}

HEADER_PREFIX = b'''#pragma once
// AUTO-GENERATED from vendor/pqc/dilithium_wasm.js by
// scripts/verify-pqc-provenance.py --write-embedded-header. Do not edit.
#include <cstddef>
#include <string>
namespace veld {
inline constexpr char kDilithiumWasmJSData[] = R"VELDDILITHIUM('''
HEADER_SUFFIX = b''')VELDDILITHIUM";
inline constexpr std::size_t kDilithiumWasmJSLen = sizeof(kDilithiumWasmJSData) - 1;
inline const std::string& GetDilithiumWasmJS() {
    static const std::string s(kDilithiumWasmJSData, kDilithiumWasmJSLen);
    return s;
}
}  // namespace veld
'''


class VerificationError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_path(root: Path, rel: str) -> Path:
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts or str(p) != rel:
        raise VerificationError(f"unsafe or non-canonical manifest path: {rel!r}")
    resolved = (root / Path(*p.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError(f"manifest path escapes repository: {rel}") from exc
    return resolved


def build_embedded_header(js: bytes) -> bytes:
    if b')VELDDILITHIUM"' in js:
        raise VerificationError("canonical JS collides with the C++ raw-string delimiter")
    return HEADER_PREFIX + js + HEADER_SUFFIX


def pqclean_upstream_path(rel: str) -> str | None:
    prefix = "vendor/pqc/mldsa65/"
    if rel.startswith(prefix):
        name = rel[len(prefix):]
        if name == "veld_seedgen.c":
            return None
        return f"crypto_sign/ml-dsa-65/clean/{name}"
    prefix = "vendor/pqc/mlkem768/"
    if rel.startswith(prefix):
        name = rel[len(prefix):]
        if name == "compat.h":
            return "common/compat.h"
        return f"crypto_kem/ml-kem-768/clean/{name}"
    if rel in {
        "vendor/pqc/fips202.c",
        "vendor/pqc/fips202.h",
        "vendor/pqc/randombytes.c",
        "vendor/pqc/randombytes.h",
    }:
        return "common/" + rel.rsplit("/", 1)[1]
    return None


def compiled_headers(root: Path) -> set[str]:
    result = {
        "vendor/pqc/fips202.h",
        "vendor/pqc/randombytes.h",
    }
    result.update(
        p.relative_to(root).as_posix()
        for p in (root / "vendor/pqc/mldsa65").glob("*.h")
    )
    return result


def coverage(root: Path) -> set[str]:
    vendor_root = root / "vendor/pqc"
    result = {
        p.relative_to(root).as_posix()
        for p in vendor_root.rglob("*")
        if p.is_file() and p.relative_to(root).as_posix() != str(MANIFEST_REL)
    }
    result.update(FIXED_COVERAGE)
    return result


def role_for(root: Path, rel: str) -> str:
    if rel in COMPILED_C:
        return "compiled-c"
    if rel in compiled_headers(root):
        return "compiled-header"
    if rel == str(CANONICAL_JS_REL):
        return "generated-js-wasm"
    if rel == str(EMBEDDED_HEADER_REL):
        return "generated-cpp-header"
    if rel == str(KAT_HEADER_REL):
        return "generated-kat-header"
    if rel == str(KAT_GENERATOR_REL):
        return "kat-generator"
    if rel == str(VENDORED_REL) or rel in {str(p) for p in VENDORED_PIN_RELS}:
        return "pinned-crypto-header"
    if rel.startswith("build/"):
        return "build-controller"
    if rel == "scripts/verify-pqc-provenance.py":
        return "verification-tool"
    if rel in {"scripts/rebuild-pqc-wasm.py", "scripts/rebuild-pqc-wasm.sh"}:
        return "rebuild-tool"
    if rel.endswith("TOOLCHAIN.lock"):
        return "toolchain-lock"
    if rel.endswith("release-c-sources.txt"):
        return "source-list"
    if rel.endswith("wasm-rebuild-attestation.tsv"):
        return "rebuild-attestation"
    if "/vendor-patches/" in rel:
        return "patch-record"
    if rel.endswith("PQCLEAN_VERSION") or rel.endswith("README.md"):
        return "provenance-record"
    if (
        rel == "THIRD_PARTY_NOTICES.md"
        or rel.endswith("LICENSE")
        or rel == "third_party_licenses/Emscripten-LICENSE.txt"
    ):
        return "license-notice"
    if rel.startswith("tests/"):
        return "regression-test"
    if rel.endswith(".c"):
        return "distributed-c"
    if rel.endswith(".h"):
        return "distributed-header"
    return "distributed-source"


def git_show(upstream: Path, object_name: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(upstream), "show", object_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise VerificationError(
            f"git show failed for {object_name}: "
            + proc.stderr.decode("utf-8", "replace").strip()
        )
    return proc.stdout


def load_manifest(root: Path) -> list[dict[str, str]]:
    manifest = root / Path(*MANIFEST_REL.parts)
    if not manifest.is_file():
        raise VerificationError(f"missing provenance manifest: {MANIFEST_REL}")
    with manifest.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        expected = [
            "sha256",
            "role",
            "origin",
            "upstream_revision",
            "upstream_path",
            "upstream_sha256",
            "patch",
            "path",
        ]
        if reader.fieldnames != expected:
            raise VerificationError(
                "provenance manifest columns differ from the required schema"
            )
        rows = list(reader)
    if not rows:
        raise VerificationError("empty provenance manifest")
    return rows


def parse_key_value_tsv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if line.endswith("\r"):
                line = line[:-1]
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 2 or not fields[0] or fields[0] in values:
                raise VerificationError(f"malformed {path.name} line {lineno}")
            values[fields[0]] = fields[1]
    return values


def parse_toolchain_lock(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise VerificationError(f"malformed toolchain lock line {lineno}")
        key, value = line.split("=", 1)
        if not key or key in values:
            raise VerificationError(f"duplicate/empty toolchain lock key line {lineno}")
        values[key] = value
    return values


def verify_toolchain_lock(root: Path) -> None:
    lock = parse_toolchain_lock(
        root / "vendor/pqc/provenance/TOOLCHAIN.lock"
    )
    exact = {
        "format": "VELD_PQC_TOOLCHAIN_V1",
        "attested_rebuild_platform": "windows-x86_64",
        "attested_toolchain_identity": TOOLCHAIN_IDENTITY,
        "emsdk_git_revision": EMSDK_REVISION,
        "emscripten_version": EMCC_VERSION,
        "container_manifest_digest": EMSDK_IMAGE.split("@", 1)[1],
        "sha256_dot_emscripten": (
            "cf771ef7a46b1c7ce1d36454f94d6643bbc034635831bcc1f10559ec260cbc2b"
        ),
        "bytes_dot_emscripten": "339",
    }
    for key, expected in exact.items():
        if lock.get(key) != expected:
            raise VerificationError(f"toolchain lock identity mismatch: {key}")
    tree_names = (
        "upstream_emscripten",
        "upstream_bin",
        "node_22_16_0_64bit",
        "python_3_13_3_64bit",
    )
    for name in tree_names:
        digest = lock.get(f"tree_{name}_sha256", "")
        count = lock.get(f"tree_{name}_files", "")
        size = lock.get(f"tree_{name}_bytes", "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise VerificationError(f"toolchain tree digest missing/malformed: {name}")
        if not count.isdigit() or int(count) <= 0 or not size.isdigit() or int(size) <= 0:
            raise VerificationError(f"toolchain tree dimensions invalid: {name}")


def wasm_input_digest(root: Path) -> str:
    inputs = set(COMPILED_C)
    inputs.update(compiled_headers(root))
    inputs.update(
        {
            "scripts/rebuild-pqc-wasm.py",
            "scripts/rebuild-pqc-wasm.sh",
            "vendor/pqc/provenance/TOOLCHAIN.lock",
            "vendor/pqc/provenance/release-c-sources.txt",
        }
    )
    h = hashlib.sha256()
    h.update(b"VELD_PQC_WASM_INPUTS_V1\0")
    for rel in sorted(inputs):
        data = safe_path(root, rel).read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def verify_attestation(root: Path, require_rebuild: bool) -> str:
    values = parse_key_value_tsv(root / Path(*ATTESTATION_REL.parts))
    required = {
        "status",
        "toolchain_identity",
        "rebuild_platform",
        "emsdk_revision",
        "emcc_version",
        "input_digest",
        "artifact_sha256",
        "embedded_header_sha256",
        "rebuild_command",
        "runtime_smoke",
        "reason",
    }
    if set(values) != required:
        missing = sorted(required - set(values))
        extra = sorted(set(values) - required)
        raise VerificationError(
            f"WASM attestation schema mismatch; missing={missing} extra={extra}"
        )
    if values["toolchain_identity"] != TOOLCHAIN_IDENTITY:
        raise VerificationError("WASM attestation toolchain identity is not pinned")
    if values["rebuild_platform"] != "windows-x86_64":
        raise VerificationError("WASM attestation rebuild platform is not pinned")
    if values["emsdk_revision"] != EMSDK_REVISION:
        raise VerificationError("WASM attestation emsdk revision is not pinned")
    if values["emcc_version"] != EMCC_VERSION:
        raise VerificationError("WASM attestation emcc version is not pinned")
    if values["rebuild_command"] != "scripts/rebuild-pqc-wasm.py":
        raise VerificationError("WASM attestation rebuild command is not canonical")
    status = values["status"]
    if status not in {"PASS", "NOT_RUN"}:
        raise VerificationError(f"invalid WASM rebuild status: {status}")
    if status == "PASS":
        if values["runtime_smoke"] != "PASS":
            raise VerificationError("WASM rebuild runtime smoke did not pass")
        expected_input = wasm_input_digest(root)
        if values["input_digest"] != expected_input:
            raise VerificationError("WASM rebuild input digest is stale")
        js_hash = sha256_file(root / Path(*CANONICAL_JS_REL.parts))
        header_hash = sha256_file(root / Path(*EMBEDDED_HEADER_REL.parts))
        if values["artifact_sha256"] != js_hash:
            raise VerificationError("WASM rebuild artifact hash is stale")
        if values["embedded_header_sha256"] != header_hash:
            raise VerificationError("WASM embedded-header attestation is stale")
    elif require_rebuild:
        raise VerificationError(
            "desktop/GUI release requires a PASS WASM rebuild attestation; "
            f"current status is NOT_RUN ({values['reason']})"
        )
    return status


def verify_patch_reconstruction(
    root: Path,
    rel: str,
    patch_rel: str,
    upstream_bytes: bytes | None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="veld-pqc-patch-") as td:
        temp_root = Path(td)
        target = safe_path(temp_root, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if upstream_bytes is not None:
            target.write_bytes(upstream_bytes)
        proc = subprocess.run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "apply",
                "--unsafe-paths",
                "--whitespace=nowarn",
                str(safe_path(root, patch_rel)),
            ],
            cwd=temp_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            raise VerificationError(
                f"recorded patch does not apply for {rel}: "
                + proc.stderr.decode("utf-8", "replace").strip()
            )
        if not target.is_file() or target.read_bytes() != safe_path(root, rel).read_bytes():
            raise VerificationError(f"recorded patch does not reconstruct {rel}")


def verify_package(root: Path, package: Path, release_role: str | None) -> None:
    if release_role is None:
        raise VerificationError("--package-dir requires --release-role")
    if not package.is_dir() or package.is_symlink():
        raise VerificationError("staged third-party package directory is missing/unsafe")
    expected: dict[str, Path] = {
        "THIRD_PARTY_NOTICES.md": root / "THIRD_PARTY_NOTICES.md",
        "licenses/PQClean-ML-DSA-65-LICENSE": root / "vendor/pqc/mldsa65/LICENSE",
        "licenses/PQClean-ML-KEM-768-LICENSE": root / "vendor/pqc/mlkem768/LICENSE",
        "provenance/PQCLEAN_VERSION": root / "vendor/pqc/PQCLEAN_VERSION",
    }
    provenance = root / "vendor/pqc/provenance"
    for source in provenance.rglob("*"):
        if source.is_file():
            rel = source.relative_to(provenance).as_posix()
            expected[f"provenance/pqc/{rel}"] = source
    for rel in (
        "scripts/generate-mldsa65-nist-kat.py",
        "scripts/rebuild-pqc-wasm.py",
        "scripts/rebuild-pqc-wasm.sh",
        "scripts/verify-pqc-provenance.py",
    ):
        expected[f"provenance/tools/{Path(rel).name}"] = root / rel
    if release_role in {"desktop", "gui"}:
        expected["licenses/Emscripten-LICENSE.txt"] = (
            root / "third_party_licenses/Emscripten-LICENSE.txt"
        )

    actual: set[str] = set()
    for path in package.rglob("*"):
        if path.is_symlink():
            raise VerificationError(f"staged package contains a symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(package).as_posix())
    if actual != set(expected):
        raise VerificationError(
            "staged PQC package coverage mismatch; "
            f"missing={sorted(set(expected) - actual)} "
            f"extra={sorted(actual - set(expected))}"
        )
    for rel, source in expected.items():
        staged = package / Path(*PurePosixPath(rel).parts)
        if staged.read_bytes() != source.read_bytes():
            raise VerificationError(f"staged PQC package raw-byte mismatch: {rel}")


def verify(
    root: Path,
    upstream: Path | None,
    release_role: str | None,
    package_dir: Path | None,
) -> tuple[int, str]:
    rows = load_manifest(root)
    expected_paths = coverage(root)
    seen: set[str] = set()
    upstream_rows = 0
    patch_rows = 0

    for row in rows:
        rel = row["path"]
        if rel in seen:
            raise VerificationError(f"duplicate manifest path: {rel}")
        seen.add(rel)
        path = safe_path(root, rel)
        if not path.is_file():
            raise VerificationError(f"manifested path is missing: {rel}")
        if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise VerificationError(f"invalid raw SHA-256 for {rel}")
        actual = sha256_file(path)
        if actual != row["sha256"]:
            raise VerificationError(
                f"raw-byte mismatch for {rel}: expected {row['sha256']}, got {actual}"
            )
        expected_role = role_for(root, rel)
        if row["role"] != expected_role:
            raise VerificationError(
                f"role mismatch for {rel}: expected {expected_role}, got {row['role']}"
            )

        upstream_path = row["upstream_path"]
        mapped = pqclean_upstream_path(rel)
        patch_rel = row["patch"]
        if rel == str(KAT_HEADER_REL):
            upstream_rows += 1
            if row["origin"] != "PQClean-generated":
                raise VerificationError("ML-DSA KAT origin is not PQClean-generated")
            if row["upstream_revision"] != PQClean_REVISION:
                raise VerificationError("ML-DSA KAT upstream revision mismatch")
            if upstream_path != KAT_META_PATH:
                raise VerificationError("ML-DSA KAT source metadata path mismatch")
            if row["upstream_sha256"] != KAT_META_SHA256:
                raise VerificationError("ML-DSA KAT metadata raw hash mismatch")
            if patch_rel != "-":
                raise VerificationError("generated ML-DSA KAT must not claim a patch")
        elif mapped is not None:
            upstream_rows += 1
            if row["origin"] != "PQClean":
                raise VerificationError(f"upstream origin mismatch for {rel}")
            if row["upstream_revision"] != PQClean_REVISION:
                raise VerificationError(f"upstream revision mismatch for {rel}")
            if upstream_path != mapped:
                raise VerificationError(f"upstream path mismatch for {rel}")
            if not re.fullmatch(r"[0-9a-f]{64}", row["upstream_sha256"]):
                raise VerificationError(f"invalid upstream raw SHA-256 for {rel}")
            expected_patch = PATCHES.get(rel, "-")
            if patch_rel != expected_patch:
                raise VerificationError(f"patch mapping mismatch for {rel}")
            if patch_rel != "-":
                patch_rows += 1
        else:
            if row["upstream_revision"] != "-" or upstream_path != "-":
                raise VerificationError(f"unexpected upstream claim for local item {rel}")
            if row["upstream_sha256"] != "-":
                raise VerificationError(f"unexpected upstream hash for local item {rel}")
            expected_patch = PATCHES.get(rel, "-")
            if patch_rel != expected_patch:
                raise VerificationError(f"local patch mapping mismatch for {rel}")
            if patch_rel != "-":
                patch_rows += 1

    if seen != expected_paths:
        missing = sorted(expected_paths - seen)
        extra = sorted(seen - expected_paths)
        raise VerificationError(
            f"manifest coverage mismatch; missing={missing} extra={extra}"
        )

    source_list = [
        line.strip()
        for line in safe_path(root, str(SOURCE_LIST_REL)).read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if tuple(source_list) != COMPILED_C:
        raise VerificationError("release C source list differs from the canonical order")

    for controller_rel in (
        "build/mainnet-v2-linux.sh",
        "build/mainnet-v2-windows.sh",
    ):
        controller = safe_path(root, controller_rel).read_text(encoding="utf-8")
        gate = '--root "$src" --release-role'
        positions = [m.start() for m in re.finditer(re.escape(gate), controller)]
        if len(positions) != 2 or controller.count("--release-role") != 2:
            raise VerificationError(
                f"{controller_rel} must contain exact precompile and prepackage gates"
            )
        compile_sources = controller.find("mapfile -t c_sources")
        first_compile = controller.find(" -c \"$src/$rel\"")
        package_boundary = controller.find('file "$artifact"')
        if not (
            0 <= positions[0] < compile_sources < first_compile < positions[1]
            < package_boundary
        ):
            raise VerificationError(
                f"{controller_rel} PQC gates do not bracket compile/package work"
            )
        if controller.count("vendor/pqc/provenance/release-c-sources.txt") != 1:
            raise VerificationError(
                f"{controller_rel} does not consume the canonical C source list"
            )
        package_copy = controller.find('third_party="$output/third-party"')
        if not (first_compile < package_copy < positions[1]):
            raise VerificationError(
                f"{controller_rel} does not stage PQC notices/provenance before its package gate"
            )

    js = safe_path(root, str(CANONICAL_JS_REL)).read_bytes()
    header = safe_path(root, str(EMBEDDED_HEADER_REL)).read_bytes()
    expected_header = build_embedded_header(js)
    if header != expected_header:
        raise VerificationError(
            "embedded Dilithium JS header is not the deterministic encoding of "
            "vendor/pqc/dilithium_wasm.js"
        )

    vendored = safe_path(root, str(VENDORED_REL)).read_bytes()
    vendored_digest = sha256_bytes(vendored)
    pin_names = (
        "VENDORED_SHA256_HEX",
        "VENDORED_SHA256_EXPECTED",
        "VENDORED_PIN_HISTORY_TIP",
    )
    for pin_rel, symbol in zip(VENDORED_PIN_RELS, pin_names):
        pin_text = safe_path(root, str(pin_rel)).read_text(encoding="utf-8")
        match = re.search(
            re.escape(symbol) + r'\s*=\s*\n?\s*"([0-9a-f]{64})"', pin_text
        )
        if match is None or match.group(1) != vendored_digest:
            raise VerificationError(
                f"{pin_rel} does not equal the raw vendored.h SHA-256"
            )
        if "pin-vendored.py" in pin_text:
            raise VerificationError(f"{pin_rel} references the absent legacy pin tool")
    vendored_text = vendored.decode("utf-8")
    if "pin-vendored.py" in vendored_text or "regenerate the pin BEFORE" in vendored_text:
        raise VerificationError("vendored.h retains a false legacy regeneration claim")
    kat_header = safe_path(root, str(KAT_HEADER_REL)).read_text(encoding="ascii")
    if KAT_RESPONSE_SHA256 not in kat_header or PQClean_REVISION not in kat_header:
        raise VerificationError("ML-DSA KAT header lacks its exact source identity")

    version_text = safe_path(root, "vendor/pqc/PQCLEAN_VERSION").read_text(
        encoding="utf-8"
    )
    if f"PQCLEAN_UPSTREAM_COMMIT={PQClean_REVISION}" not in version_text:
        raise VerificationError("PQCLEAN_VERSION does not carry the canonical revision")

    verify_toolchain_lock(root)

    require_rebuild = release_role in {"desktop", "gui"}
    wasm_status = verify_attestation(root, require_rebuild=require_rebuild)

    if package_dir is not None:
        verify_package(root, package_dir, release_role)

    if upstream is not None:
        head = subprocess.run(
            ["git", "-C", str(upstream), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if head.returncode != 0 or head.stdout.strip() != PQClean_REVISION:
            raise VerificationError(
                f"upstream checkout is not exact commit {PQClean_REVISION}"
            )
        row_by_path = {row["path"]: row for row in rows}
        for rel, row in row_by_path.items():
            if rel == str(KAT_HEADER_REL):
                raw = git_show(upstream, f"{PQClean_REVISION}:{KAT_META_PATH}")
                if sha256_bytes(raw) != row["upstream_sha256"]:
                    raise VerificationError("ML-DSA KAT source metadata hash mismatch")
                continue
            mapped = pqclean_upstream_path(rel)
            if mapped is None:
                if row["patch"] != "-":
                    verify_patch_reconstruction(root, rel, row["patch"], None)
                continue
            raw = git_show(upstream, f"{PQClean_REVISION}:{mapped}")
            if sha256_bytes(raw) != row["upstream_sha256"]:
                raise VerificationError(f"upstream raw-byte hash mismatch for {mapped}")
            if row["patch"] == "-":
                if raw != safe_path(root, rel).read_bytes():
                    raise VerificationError(
                        f"{rel} differs from upstream without a recorded patch"
                    )
            else:
                verify_patch_reconstruction(root, rel, row["patch"], raw)

        kat = subprocess.run(
            [
                sys.executable,
                str(safe_path(root, str(KAT_GENERATOR_REL))),
                "--root",
                str(root),
                "--upstream-dir",
                str(upstream),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if kat.returncode != 0:
            raise VerificationError(
                "ML-DSA KAT source regeneration failed: " + kat.stderr.strip()
            )

    return len(rows), wasm_status


def write_manifest(root: Path, upstream: Path) -> None:
    head = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if head.returncode != 0 or head.stdout.strip() != PQClean_REVISION:
        raise VerificationError(
            f"--write-manifest requires exact PQClean checkout {PQClean_REVISION}"
        )

    rows: list[list[str]] = []
    for rel in sorted(coverage(root)):
        path = safe_path(root, rel)
        if not path.is_file():
            raise VerificationError(f"required provenance input is missing: {rel}")
        mapped = pqclean_upstream_path(rel)
        if rel == str(KAT_HEADER_REL):
            origin = "PQClean-generated"
            revision = PQClean_REVISION
            upstream_path = KAT_META_PATH
            raw = git_show(upstream, f"{PQClean_REVISION}:{KAT_META_PATH}")
            upstream_hash = sha256_bytes(raw)
        elif mapped is None:
            origin = "Emscripten-generated" if rel in {
                str(CANONICAL_JS_REL), str(EMBEDDED_HEADER_REL)
            } else "Veld"
            revision = upstream_path = upstream_hash = "-"
        else:
            origin = "PQClean"
            revision = PQClean_REVISION
            upstream_path = mapped
            raw = git_show(upstream, f"{PQClean_REVISION}:{mapped}")
            upstream_hash = sha256_bytes(raw)
            patch_rel = PATCHES.get(rel)
            if patch_rel is None and raw != path.read_bytes():
                raise VerificationError(
                    f"unrecorded local modification while writing manifest: {rel}"
                )
        rows.append(
            [
                sha256_file(path),
                role_for(root, rel),
                origin,
                revision,
                upstream_path,
                upstream_hash,
                PATCHES.get(rel, "-"),
                rel,
            ]
        )

    manifest = root / Path(*MANIFEST_REL.parts)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(
            [
                "sha256",
                "role",
                "origin",
                "upstream_revision",
                "upstream_path",
                "upstream_sha256",
                "patch",
                "path",
            ]
        )
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to this script's repository)",
    )
    parser.add_argument(
        "--upstream-dir",
        type=Path,
        help="optional exact PQClean checkout for upstream/patch reconstruction",
    )
    parser.add_argument(
        "--release-role",
        choices=(
            "node",
            "desktop",
            "keygen",
            "validator",
            "operator",
            "gui",
            "fleet",
        ),
        help="enforce role-specific release prerequisites",
    )
    parser.add_argument(
        "--package-dir",
        type=Path,
        help="verify the staged third-party package directory byte-for-byte",
    )
    parser.add_argument(
        "--write-embedded-header",
        action="store_true",
        help="rewrite the deterministic C++ header from the canonical JS bytes",
    )
    parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="rewrite the raw-byte manifest (requires --upstream-dir)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.write_embedded_header:
            js = safe_path(root, str(CANONICAL_JS_REL)).read_bytes()
            safe_path(root, str(EMBEDDED_HEADER_REL)).write_bytes(
                build_embedded_header(js)
            )
        if args.write_manifest:
            if args.upstream_dir is None:
                raise VerificationError("--write-manifest requires --upstream-dir")
            write_manifest(root, args.upstream_dir.resolve())
        rows, wasm_status = verify(
            root,
            args.upstream_dir.resolve() if args.upstream_dir else None,
            args.release_role,
            args.package_dir.resolve() if args.package_dir else None,
        )
        print(
            "PASS PQC provenance "
            f"items={rows} pqclean_revision={PQClean_REVISION} "
            f"wasm_rebuild={wasm_status}"
        )
        return 0
    except (OSError, VerificationError, UnicodeError) as exc:
        print(f"FAIL PQC provenance: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
