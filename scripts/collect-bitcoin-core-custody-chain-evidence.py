#!/usr/bin/env python3
"""Collect a fail-closed Bitcoin Core best-chain snapshot for custody drills.

This Linux ceremony helper talks only to an already-running, locally attached
native Bitcoin Core daemon.  It never signs or broadcasts.  The resulting
canonical JSON is consumed by validate-funded-custody-drill.py and must be
hash-bound by the detached-signed parent custody report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX160 = re.compile(r"^[0-9a-f]{160}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{2,127}$")
POW_LIMIT = int(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
MAX_EVIDENCE_TARGET = POW_LIMIT // 1_000_000_000_000
COLLECTOR_VERSION = "collect-bitcoin-core-custody-evidence-v1"


class CollectionError(ValueError):
    pass


def fail(message: str) -> None:
    raise CollectionError(message)


def hash256(raw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key in Bitcoin Core response: {key}")
        value[key] = item
    return value


def parse_json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=strict_object)
    except (ValueError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {label}: {exc}")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def pinned_binary(path: Path, wanted_sha256: str, wanted_name: str) -> Path:
    if not path.is_absolute() or not HEX64.fullmatch(wanted_sha256):
        fail(f"{wanted_name} requires an absolute path and lowercase SHA-256")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = resolved.stat()
    except OSError as exc:
        fail(f"cannot inspect {wanted_name}: {exc}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(after.st_mode):
        fail(f"{wanted_name} must be a regular non-symlink file")
    if resolved.name != wanted_name:
        fail(f"{wanted_name} resolved executable name is not exact")
    if sha256_file(resolved) != wanted_sha256:
        fail(f"{wanted_name} SHA-256 differs from the independent pin")
    return resolved


def daemon_identity(pid: int, daemon: Path) -> tuple[int, int]:
    if sys.platform != "linux" or pid <= 1:
        fail("the custody chain collector requires a Linux bitcoind PID")
    proc = Path("/proc") / str(pid)
    try:
        executable = Path(os.readlink(proc / "exe")).resolve(strict=True)
        status = (proc / "status").read_text(encoding="ascii")
        cmdline = (proc / "cmdline").read_bytes().split(b"\0")
        stat_text = (proc / "stat").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot inspect bitcoind PID {pid}: {exc}")
    if executable != daemon:
        fail("bitcoind PID executable differs from the pinned daemon")
    uid_match = re.search(r"(?m)^Uid:\s+(\d+)\s", status)
    if uid_match is None or int(uid_match.group(1)) != os.getuid():
        fail("bitcoind PID is not owned by the collector user")
    decoded = []
    for item in cmdline:
        if not item:
            continue
        try:
            decoded.append(item.decode("utf-8"))
        except UnicodeError:
            fail("bitcoind command line is not UTF-8")
    lowered = [item.lower() for item in decoded[1:]]
    forbidden = (
        "-regtest", "-testnet", "-testnet4", "-signet", "-chain=regtest",
        "-chain=test", "-chain=testnet4", "-chain=signet",
    )
    if any(item == marker or item.startswith(marker + "=")
           for item in lowered for marker in forbidden):
        fail("bitcoind PID command line selects a non-main network")
    try:
        tail = stat_text[stat_text.rfind(")") + 2:].split()
        start_time_ticks = int(tail[19])
    except (ValueError, IndexError):
        fail("cannot parse bitcoind process start time")
    return pid, start_time_ticks


def validate_rpc_args(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if (not isinstance(value, str) or len(value) > 4096 or
                any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)):
            fail("bitcoin-cli RPC argument contains unsafe text")
        name, separator, setting = value.partition("=")
        if name not in {
                "-datadir", "-conf", "-rpcconnect", "-rpcport",
                "-rpccookiefile", "-rpcclienttimeout"} or not separator or not setting:
            fail(f"bitcoin-cli RPC argument is not allowed: {name}")
        if name in seen:
            fail(f"bitcoin-cli RPC argument is duplicated: {name}")
        seen.add(name)
        if name == "-rpcconnect" and setting not in ("127.0.0.1", "::1", "localhost"):
            fail("bitcoin-cli must connect only to a loopback RPC endpoint")
        if name in ("-rpcport", "-rpcclienttimeout") and not setting.isdigit():
            fail(f"bitcoin-cli {name} must be numeric")
        result.append(value)
    return result


class Rpc:
    def __init__(self, cli: Path, arguments: list[str]) -> None:
        self.cli = cli
        self.arguments = arguments

    def call(self, method: str, *arguments: str) -> str:
        try:
            result = subprocess.run(
                [str(self.cli), *self.arguments, method, *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=120, check=False,
                env={
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "LANG": "C", "LC_ALL": "C",
                },
            )
        except (OSError, subprocess.SubprocessError) as exc:
            fail(f"bitcoin-cli {method} could not run: {exc}")
        if result.returncode != 0:
            detail = result.stderr.strip().replace("\n", " ")[:500]
            fail(f"bitcoin-cli {method} failed ({result.returncode}): {detail}")
        if result.stderr:
            fail(f"bitcoin-cli {method} produced unexpected stderr")
        return result.stdout.strip()

    def json(self, method: str, *arguments: str) -> Any:
        return parse_json(self.call(method, *arguments), method)


def exact_chain_info(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("getblockchaininfo did not return an object")
    required = ("chain", "blocks", "headers", "bestblockhash",
                "initialblockdownload")
    if (value.get("chain") != "main" or
            type(value.get("blocks")) is not int or value["blocks"] < 0 or
            type(value.get("headers")) is not int or
            value["headers"] != value["blocks"] or
            not isinstance(value.get("bestblockhash"), str) or
            HEX64.fullmatch(value["bestblockhash"]) is None or
            value.get("initialblockdownload") is not False):
        fail("Bitcoin Core is not a fully synced mainnet node")
    return {key: value[key] for key in required}


def target_to_compact(target: int) -> int:
    size = (target.bit_length() + 7) // 8
    compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    compact &= 0xFFFFFF
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | size << 24


def verify_header(raw_hex: str, wanted_hash: str) -> bytes:
    if not HEX160.fullmatch(raw_hex):
        fail("getblockheader false did not return lowercase 80-byte hex")
    raw = bytes.fromhex(raw_hex)
    if hash256(raw)[::-1].hex() != wanted_hash:
        fail("getblockheader raw bytes differ from the requested block hash")
    bits = int.from_bytes(raw[72:76], "little")
    size, word = bits >> 24, bits & 0x007FFFFF
    if bits & 0x00800000 or word == 0:
        fail("Bitcoin header compact target is negative or zero")
    target = word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))
    if (target <= 0 or target > MAX_EVIDENCE_TARGET or
            target_to_compact(target) != bits):
        fail("Bitcoin header target is non-canonical or below the evidence floor")
    if int.from_bytes(hash256(raw), "little") > target:
        fail("Bitcoin header does not satisfy proof of work")
    return raw


def exclusive_write(path: Path, raw: bytes) -> None:
    if not path.is_absolute():
        fail("output path must be absolute")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        fail("output parent must be a regular non-symlink directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        fail(f"cannot exclusively write chain evidence: {exc}")


def collect(args: argparse.Namespace) -> dict[str, Any]:
    cli = pinned_binary(args.bitcoin_cli, args.bitcoin_cli_sha256, "bitcoin-cli")
    daemon = pinned_binary(args.bitcoind, args.bitcoind_sha256, "bitcoind")
    pid, start_ticks = daemon_identity(args.bitcoind_pid, daemon)
    rpc_args = validate_rpc_args(args.rpc_arg)
    if len(args.txid) != 6 or len(set(args.txid)) != 6 or any(
            HEX64.fullmatch(item) is None for item in args.txid):
        fail("exactly six distinct lowercase custody transaction IDs are required")
    if IDENTITY.fullmatch(args.node_id or "") is None:
        fail("node-id is not canonical")
    rpc = Rpc(cli, rpc_args)
    before = exact_chain_info(rpc.json("getblockchaininfo"))
    network = rpc.json("getnetworkinfo")
    if (not isinstance(network, dict) or type(network.get("version")) is not int or
            network["version"] <= 0 or not isinstance(network.get("subversion"), str) or
            not 1 <= len(network["subversion"]) <= 100):
        fail("getnetworkinfo did not return a canonical node version")

    references = []
    for txid in args.txid:
        proof_hex = rpc.call(
            "gettxoutproof", json.dumps([txid], separators=(",", ":")))
        if not re.fullmatch(r"(?:[0-9a-f]{2}){80,}", proof_hex):
            fail(f"gettxoutproof for {txid} is not canonical hex")
        block_hash = hash256(bytes.fromhex(proof_hex)[:80])[::-1].hex()
        verbose = rpc.json("getblockheader", block_hash, "true")
        if (not isinstance(verbose, dict) or verbose.get("hash") != block_hash or
                type(verbose.get("height")) is not int or verbose["height"] < 0 or
                type(verbose.get("confirmations")) is not int or
                verbose["confirmations"] < 6):
            fail(f"custody transaction {txid} is not six-deep in the best chain")
        references.append({
            "txid": txid, "block_hash": block_hash,
            "height": verbose["height"], "proof_hex": proof_hex,
        })
    minimum_height = min(item["height"] for item in references)
    if before["blocks"] - minimum_height + 1 > 1000:
        fail("custody block-to-tip segment exceeds the 1,000-header evidence bound")

    headers = []
    raw_by_hash = {}
    previous_hash = None
    for height in range(minimum_height, before["blocks"] + 1):
        block_hash = rpc.call("getblockhash", str(height))
        if HEX64.fullmatch(block_hash) is None:
            fail(f"getblockhash {height} returned a noncanonical hash")
        raw_hex = rpc.call("getblockheader", block_hash, "false")
        raw = verify_header(raw_hex, block_hash)
        if previous_hash is not None and raw[4:36][::-1].hex() != previous_hash:
            fail("Bitcoin Core header snapshot is not hash-linked")
        headers.append({
            "height": height, "requested_hash": block_hash,
            "getblockheader_false_hex": raw_hex,
        })
        raw_by_hash[block_hash] = raw
        previous_hash = block_hash

    after = exact_chain_info(rpc.json("getblockchaininfo"))
    if after != before or previous_hash != before["bestblockhash"]:
        fail("Bitcoin Core best-chain tip changed during evidence collection; retry")
    proofs = []
    for reference in references:
        if rpc.call("getblockhash", str(reference["height"])) != reference["block_hash"]:
            fail("custody transaction block left the best chain during collection; retry")
        repeated = rpc.call(
            "gettxoutproof",
            json.dumps([reference["txid"]], separators=(",", ":")),
            reference["block_hash"])
        if repeated != reference["proof_hex"]:
            fail("custody transaction proof changed during evidence collection; retry")
        if repeated[:160] != raw_by_hash[reference["block_hash"]].hex():
            fail("custody transaction proof header differs from the best-chain snapshot")
        confirmations = before["blocks"] - reference["height"] + 1
        if confirmations < 6:
            fail("custody transaction lost six-confirmation depth during collection")
        proofs.append({
            "txid": reference["txid"], "block_hash": reference["block_hash"],
            "gettxoutproof_hex": repeated,
        })
    if daemon_identity(pid, daemon)[1] != start_ticks:
        fail("bitcoind process identity changed during evidence collection; retry")
    if sha256_file(cli) != args.bitcoin_cli_sha256 or \
            sha256_file(daemon) != args.bitcoind_sha256:
        fail("pinned Bitcoin Core executable bytes changed during collection")

    return {
        "schema": 1,
        "statement": "veld-bitcoin-core-mainnet-custody-chain-evidence-v1",
        "result": "PASS",
        "bitcoin_network": "main",
        "node_id": args.node_id,
        "node_version": f"version={network['version']};subversion={network['subversion']}",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "collector_version": COLLECTOR_VERSION,
        "bitcoin_cli_path": str(cli),
        "bitcoin_cli_sha256": args.bitcoin_cli_sha256,
        "bitcoind_path": str(daemon),
        "bitcoind_sha256": args.bitcoind_sha256,
        "bitcoind_pid": pid,
        "bitcoind_start_time_ticks": start_ticks,
        "rpc_arguments_sha256": hashlib.sha256(canonical_bytes(rpc_args)).hexdigest(),
        "getblockchaininfo": before,
        "headers": headers,
        "txoutproofs": proofs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoin-cli", required=True, type=Path)
    parser.add_argument("--bitcoin-cli-sha256", required=True)
    parser.add_argument("--bitcoind", required=True, type=Path)
    parser.add_argument("--bitcoind-sha256", required=True)
    parser.add_argument("--bitcoind-pid", required=True, type=int)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--rpc-arg", action="append", default=[])
    parser.add_argument("--txid", action="append", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        document = collect(args)
        exclusive_write(args.output, canonical_bytes(document))
    except (CollectionError, OSError, UnicodeError) as exc:
        print(f"BITCOIN-CUSTODY-CHAIN-COLLECT FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "BITCOIN-CUSTODY-CHAIN-COLLECT OK: pinned native mainnet Core, "
        "stable tip, six proofs, and contiguous high-work headers captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
