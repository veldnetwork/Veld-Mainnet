#!/usr/bin/env python3
"""Rebuild Veld's single-file PQC WASM twice with the exact pinned emsdk."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import NoReturn


EMSDK_REVISION = "62a853cd3b3134398ce85cde8bb5cbb2ef0194cb"
EMCC_VERSION = "4.0.10"
TOOL_HASHES = {
    "upstream/emscripten/emcc.bat": "b61f25a114b9b93444de62bc31bf05d1b12b3986513c75f6b23ccc1711c6a634",
    "upstream/emscripten/emcc.py": "4b47445c680acc3ce625312f1d279d4d50347c27661fcde9b5b904a775eae9ec",
    "upstream/bin/clang.exe": "2139bce5bdd3ba2648e353d56d9e75654cf89c2dfed10ebfbc56a60979a86c55",
    "upstream/bin/wasm-ld.exe": "3b6db708d4e85e592017832b1ffd245469776bbbc4d9be50d4de9a1f3171e2fc",
    "upstream/bin/wasm-opt.exe": "7d69f7f4a46b208493ab8405309c58226b67e7905c1015069acf9001055b8a33",
    "node/22.16.0_64bit/bin/node.exe": "c5ff4c736112dd483c750fd4149d30c8a116db1a49b8b3ec88be4b65e6c86c19",
    "python/3.13.3_64bit/python.exe": "d87063e5597f257004c731b66c59c56c91038861c6877b1a3dca6b8c4e919125",
}
TOOLCHAIN_LOCK = "vendor/pqc/provenance/TOOLCHAIN.lock"
TREE_ROOTS = {
    "upstream_emscripten": "upstream/emscripten",
    "upstream_bin": "upstream/bin",
    "node_22_16_0_64bit": "node/22.16.0_64bit",
    "python_3_13_3_64bit": "python/3.13.3_64bit",
}
DOT_EMSCRIPTEN = b"""import os
emsdk_path = os.path.dirname(os.getenv('EM_CONFIG')).replace('\\\\', '/')
NODE_JS = emsdk_path + '/node/22.16.0_64bit/bin/node.exe'
PYTHON = emsdk_path + '/python/3.13.3_64bit/python.exe'
LLVM_ROOT = emsdk_path + '/upstream/bin'
BINARYEN_ROOT = emsdk_path + '/upstream'
EMSCRIPTEN_ROOT = emsdk_path + '/upstream/emscripten'
""".replace(b"\n", b"\r\n")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def parse_lock(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"malformed toolchain lock line {lineno}")
        key, value = line.split("=", 1)
        if not key or key in values:
            fail(f"duplicate/empty toolchain lock key on line {lineno}")
        values[key] = value
    return values


def tree_digest(root: Path) -> tuple[str, int, int]:
    if not root.is_dir():
        fail(f"pinned toolchain tree is missing: {root}")
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(f"pinned toolchain tree contains a symlink: {path}")
        if path.is_file():
            files.append(path)
    files.sort(key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))
    digest = hashlib.sha256(b"VELD_EMSDK_RAW_TREE_V1\0")
    total = 0
    for path in files:
        rel = path.relative_to(root).as_posix().encode("utf-8")
        size = path.stat().st_size
        total += size
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest(), len(files), total


def toolchain_measurements(emsdk: Path) -> dict[str, str]:
    config = emsdk / ".emscripten"
    if not config.is_file():
        fail("emsdk must be activated so its .emscripten configuration exists")
    if config.read_bytes() != DOT_EMSCRIPTEN:
        fail("activated .emscripten content is not the canonical relative-root config")
    measured = {
        "sha256_dot_emscripten": sha256(config),
        "bytes_dot_emscripten": str(config.stat().st_size),
    }
    for name, rel in TREE_ROOTS.items():
        digest, count, total = tree_digest(emsdk / Path(*rel.split("/")))
        measured[f"tree_{name}_sha256"] = digest
        measured[f"tree_{name}_files"] = str(count)
        measured[f"tree_{name}_bytes"] = str(total)
    return measured


def verify_toolchain(emsdk: Path, lock: dict[str, str]) -> dict[str, str]:
    status = subprocess.run(
        ["git", "-C", str(emsdk), "status", "--porcelain=v1", "--untracked-files=all"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if status.returncode != 0 or status.stdout:
        fail("emsdk Git checkout is not clean")
    measured = toolchain_measurements(emsdk)
    for key, actual in measured.items():
        expected = lock.get(key)
        if expected != actual:
            fail(f"pinned toolchain measurement mismatch: {key} expected={expected} got={actual}")
    return measured


def run_checked(command: list[str], **kwargs: object) -> None:
    print("COMMAND " + subprocess.list2cmdline(command), flush=True)
    proc = subprocess.run(command, check=False, **kwargs)
    if proc.returncode != 0:
        fail(f"command failed with exit {proc.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emsdk-root", type=Path, required=True)
    parser.add_argument("--print-toolchain-digests", action="store_true")
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    emsdk = args.emsdk_root.resolve()
    if args.print_toolchain_digests:
        for key, value in toolchain_measurements(emsdk).items():
            print(f"{key}={value}")
        return 0
    if args.output is None:
        fail("output is required unless --print-toolchain-digests is used")
    output = args.output.resolve()
    try:
        output.relative_to(repo)
    except ValueError:
        pass
    else:
        fail("output must be outside the source tree")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        fail(f"output must be absent or empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    head = subprocess.run(
        ["git", "-C", str(emsdk), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if head.returncode != 0 or head.stdout.strip() != EMSDK_REVISION:
        fail(f"emsdk checkout must be exact revision {EMSDK_REVISION}")
    lock = parse_lock(repo / TOOLCHAIN_LOCK)
    verify_toolchain(emsdk, lock)
    for rel, expected in TOOL_HASHES.items():
        path = emsdk / Path(*rel.split("/"))
        if not path.is_file():
            fail(f"pinned emsdk input is missing: {rel}")
        actual = sha256(path)
        if actual != expected:
            fail(f"pinned emsdk input mismatch: {rel} expected={expected} got={actual}")

    source_list = repo / "vendor/pqc/provenance/release-c-sources.txt"
    sources = [
        line.strip()
        for line in source_list.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not sources:
        fail("empty PQC source list")

    emcc_python = emsdk / "upstream/emscripten/emcc.py"
    pinned_python = emsdk / "python/3.13.3_64bit/python.exe"
    env = os.environ.copy()
    env["EMSDK"] = emsdk.as_posix()
    env["EMSDK_NODE"] = str(emsdk / "node/22.16.0_64bit/bin/node.exe")
    env["EMSDK_PYTHON"] = str(emsdk / "python/3.13.3_64bit/python.exe")
    env["EM_CONFIG"] = str(emsdk / ".emscripten")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PATH"] = os.pathsep.join(
        [str(emsdk), str(emsdk / "upstream/emscripten"), env.get("PATH", "")]
    )
    common = [
        "-std=gnu11",
        "-O3",
        "-DNDEBUG",
        "--no-entry",
        "-Ivendor/pqc",
        "-Ivendor/pqc/mldsa65",
        *sources,
        "-sSTRICT=1",
        "-sMODULARIZE=1",
        "-sEXPORT_NAME=VeldDilithium",
        "-sSINGLE_FILE=1",
        "-sENVIRONMENT=web,node",
        "-sFILESYSTEM=0",
        "-sALLOW_MEMORY_GROWTH=1",
        "-sSTACK_SIZE=1048576",
        "-sASSERTIONS=0",
        '-sEXPORTED_FUNCTIONS=["_PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature","_PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify","_veld_mldsa65_keypair_from_seed","_malloc","_free"]',
        '-sEXPORTED_RUNTIME_METHODS=["ccall","cwrap","HEAPU8"]',
    ]

    for name in ("rebuild-a.js", "rebuild-b.js"):
        command = [
            str(pinned_python),
            "-B",
            str(emcc_python),
            *common,
            "-o",
            str(output / name),
        ]
        run_checked(command, cwd=repo, env=env)

    first = output / "rebuild-a.js"
    second = output / "rebuild-b.js"
    canonical = repo / "vendor/pqc/dilithium_wasm.js"
    first_hash = sha256(first)
    if first_hash != sha256(second):
        fail("two exact-toolchain rebuilds are not byte-identical")
    if first.read_bytes() != canonical.read_bytes():
        fail(
            "reproducible output differs from vendor/pqc/dilithium_wasm.js; "
            f"rebuilt={first_hash} checked_in={sha256(canonical)}"
        )

    node = emsdk / "node/22.16.0_64bit/bin/node.exe"
    smoke = repo / "tests/pqc_wasm_smoke.js"
    run_checked([str(node), str(smoke), str(first)], cwd=repo, env=env)
    verify_toolchain(emsdk, lock)
    (output / "sha256.txt").write_text(
        f"{first_hash}  rebuild-a.js\n"
        f"{first_hash}  rebuild-b.js\n"
        f"{first_hash}  vendor/pqc/dilithium_wasm.js\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        "PASS deterministic PQC WASM rebuild, artifact comparison, and runtime smoke "
        f"sha256={first_hash}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as exc:
        print(f"FAIL PQC WASM rebuild: {exc}", file=sys.stderr)
        raise SystemExit(1)
