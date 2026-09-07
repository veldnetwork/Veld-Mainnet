#!/usr/bin/env python3
"""Publish an address-free network view from existing read-only peer RPCs.

This collector is intended for fleet versions that predate gui-status.json.
Peer addresses are used only in memory to join reports and are never written
to the public topology document or to routine logs.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


MAX_CONFIG_BYTES = 64 * 1024
MAX_RPC_BYTES = 256 * 1024
MAX_NODES = 256
MAX_EDGES = 1024
VALID_ROLES = {"fleet", "node", "miner", "validator"}
TIP_STALE_SECONDS = 180
ROLE_PRIORITY = {"node": 0, "miner": 1, "validator": 2}


def read_json(path: Path, limit: int) -> dict:
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise ValueError("file is empty or exceeds its size limit")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("document is not an object")
    return value


def canonical_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("peer address is not text")
    return ipaddress.ip_address(value.strip()).compressed


def anonymous_id(secret: bytes, address: str) -> int:
    digest = hmac.new(secret, address.encode("ascii"), hashlib.sha256).digest()
    value = int.from_bytes(digest[:8], "little")
    return value or 1


def rpc_result(raw: bytes) -> list[dict]:
    if not raw or len(raw) > MAX_RPC_BYTES:
        raise ValueError("RPC response is empty or too large")
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("error") is not None:
        raise ValueError("RPC returned an error")
    result = document.get("result")
    if not isinstance(result, list) or len(result) > MAX_NODES:
        raise ValueError("RPC peer result is invalid")
    return [item for item in result if isinstance(item, dict)]


def run_source(source: dict, known_hosts: str, key_file: str) -> list[dict]:
    if source.get("local") is True:
        command = ["/usr/local/sbin/veld-topology-export"]
    else:
        host = canonical_ip(source.get("host"))
        command = [
            "ssh", "-T", "-i", key_file,
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "--", f"root@{host}",
        ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=12,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("peer RPC transport failed")
    return rpc_result(completed.stdout)


def reported_role(peer: dict) -> str | None:
    """Use live advertised roles; None means no usable role report yet."""
    services = peer.get("services")
    if services == 0:
        return None  # Connected socket with VERSION still pending.
    role = peer.get("role")
    if isinstance(role, str) and role in ROLE_PRIORITY:
        return role
    if (not isinstance(services, int) or isinstance(services, bool) or
            not 0 < services < (1 << 64)):
        return None
    if services & 0x10:
        return "validator"
    if services & 0x08:
        return "miner"
    return "node"


def parse_identity(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("identity entry is not an object")
    node_id = value.get("id")
    role = value.get("role")
    role_index = value.get("role_index", 0)
    if (not isinstance(node_id, int) or isinstance(node_id, bool) or
            node_id <= 0 or node_id >= 1 << 64):
        raise ValueError("identity has an invalid id")
    if role not in VALID_ROLES:
        raise ValueError("identity has an invalid role")
    if (not isinstance(role_index, int) or isinstance(role_index, bool) or
            role_index < 0 or role_index > 999):
        raise ValueError("identity has an invalid role index")
    return {"id": node_id, "role": role, "role_index": role_index}


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
    encoded = body.encode("utf-8")
    if len(encoded) > MAX_RPC_BYTES:
        raise ValueError("topology output exceeds its public API limit")
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def collect(config: dict) -> tuple[dict, list[str]]:
    salt_file = Path(config["salt_file"])
    secret = salt_file.read_bytes()
    if len(secret) < 32 or len(secret) > 128:
        raise ValueError("collector salt has an invalid length")

    known: dict[str, dict] = {}
    for address, identity in config.get("known", {}).items():
        known[canonical_ip(address)] = parse_identity(identity)
    excluded = {canonical_ip(item) for item in config.get("excluded", [])}

    sources = config.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 32:
        raise ValueError("collector sources are invalid")

    now = int(time.time())
    nodes: dict[int, dict] = {}
    tip_reports: dict[int, list[tuple[str, int]]] = collections.defaultdict(list)
    role_reports: dict[int, set[str]] = collections.defaultdict(set)
    directed_edges: set[tuple[int, int]] = set()
    failures: list[str] = []
    reporting = 0

    def note(identity: dict, is_reporting: bool) -> None:
        node_id = identity["id"]
        current = nodes.get(node_id)
        candidate = {
            "id": node_id,
            "role": identity["role"],
            "role_index": identity["role_index"],
            "updated_at": now,
            "reporting": is_reporting,
        }
        if current is None:
            nodes[node_id] = candidate
        else:
            current["reporting"] = current["reporting"] or is_reporting
            current["updated_at"] = now

    for source in sources:
        name = source.get("name")
        if not isinstance(name, str) or not name or len(name) > 40:
            raise ValueError("source has an invalid name")
        try:
            source_address = canonical_ip(source.get("address"))
            source_identity = known[source_address]
            peers = run_source(source, config["known_hosts"], config["key_file"])
            note(source_identity, True)
            reporting += 1
            for peer in peers:
                try:
                    peer_address = canonical_ip(peer.get("ip"))
                except Exception:
                    continue
                if peer_address in excluded or peer_address == source_address:
                    continue
                identity = known.get(peer_address)
                if identity is None:
                    identity = {
                        "id": anonymous_id(secret, peer_address),
                        "role": "node",
                        "role_index": 0,
                    }
                note(identity, False)
                role = reported_role(peer)
                if role is not None and identity["role"] != "fleet":
                    role_reports[identity["id"]].add(role)
                directed_edges.add((source_identity["id"], identity["id"]))
                tip_hash = peer.get("peer_tip_hash")
                tip_age = peer.get("peer_tip_age_s")
                if (isinstance(tip_hash, str) and len(tip_hash) == 64 and
                        all(ch in "0123456789abcdefABCDEF" for ch in tip_hash) and
                        isinstance(tip_age, int) and not isinstance(tip_age, bool)):
                    tip_reports[identity["id"]].append(
                        (tip_hash.lower(), tip_age))
        except Exception as exc:
            failures.append(f"{name}: {exc}")

    if reporting == 0:
        raise RuntimeError("no fleet report was available")

    # Merge sessions and fleet reports before choosing the role. An older
    # exporter with missing metadata must not erase a current miner report.
    for node_id, roles in role_reports.items():
        node = nodes[node_id]
        role = max(roles, key=ROLE_PRIORITY.__getitem__)
        if node["role"] != role:
            node["role_index"] = 0
        node["role"] = role

    ordered = sorted(nodes.values(), key=lambda item: (not item["reporting"], item["id"]))
    ordered = ordered[:MAX_NODES]
    kept = {node["id"] for node in ordered}
    edges = []
    seen: set[tuple[int, int]] = set()
    for source_id, peer_id in sorted(directed_edges):
        if source_id not in kept or peer_id not in kept:
            continue
        pair = (min(source_id, peer_id), max(source_id, peer_id))
        if pair in seen:
            continue
        seen.add(pair)
        edges.append({
            "a": pair[0],
            "b": pair[1],
            "confirmed": (peer_id, source_id) in directed_edges,
        })
        if len(edges) >= MAX_EDGES:
            break

    recent_hashes = [tip_hash
                     for reports in tip_reports.values()
                     for tip_hash, age in reports
                     if 0 <= age <= TIP_STALE_SECONDS]
    network_tip = None
    if recent_hashes:
        counts = collections.Counter(recent_hashes).most_common(2)
        if len(counts) == 1 or counts[0][1] > counts[1][1]:
            network_tip = counts[0][0]

    public_nodes = []
    for node in ordered:
        reports = tip_reports.get(node["id"], [])
        recent = [tip_hash for tip_hash, age in reports
                  if 0 <= age <= TIP_STALE_SECONDS]
        if not reports:
            tip_state = "unavailable"
        elif not recent:
            tip_state = "stale"
        elif network_tip is None:
            tip_state = "unavailable"
        else:
            counts = collections.Counter(recent).most_common(2)
            if len(counts) > 1 and counts[0][1] == counts[1][1]:
                tip_state = "unavailable"
            else:
                tip_state = "exact" if counts[0][0] == network_tip else "differs"
        public_nodes.append({
            "id": node["id"],
            "role": node["role"],
            "role_index": node["role_index"],
            "updated_at": node["updated_at"],
            "tip_state": tip_state,
        })
    return {
        "schema": 1,
        "generated_at": now,
        "reporting_nodes": reporting,
        "eligible_nodes": len(public_nodes),
        "nodes": public_nodes,
        "edges": edges,
    }, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config_path = Path(args.config)
    try:
        config = read_json(config_path, MAX_CONFIG_BYTES)
        output = Path(config["output"])
        payload, failures = collect(config)
        atomic_write(output, payload)
    except Exception as exc:
        print(f"topology collector: {exc}; existing output preserved", file=sys.stderr)
        return 1
    print(
        "topology collector: published "
        f"{payload['reporting_nodes']} report(s), "
        f"{payload['eligible_nodes']} node(s), {len(payload['edges'])} edge(s)"
    )
    for failure in failures:
        print(f"topology collector: skipped {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
