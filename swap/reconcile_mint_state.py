#!/usr/bin/env python3
"""Offline, two-operator migration for pre-witness issuer signer state.

This command never guesses that an old signature is harmless.  It requires a
review artifact bound to the exact old-state bytes, a coherent chain/custody
inventory, a >MAX_REORG_DEPTH quiescence wait, and two cryptographic operator
approvals.  The old file is retained byte-for-byte and resolved rows become audit
tombstones; they are never silently deleted.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
import sys

sys.path.insert(0, HERE)
import veld_signerd as signer  # noqa: E402

ARTIFACT_VERSION = 1
ARTIFACT_KIND = "VELD_LEGACY_MINT_RECONCILIATION"


def fail(message):
    raise RuntimeError(str(message))


def regular_bytes(path, private=False, max_bytes=16 * 1024 * 1024):
    if not os.path.isabs(path):
        fail("path must be absolute: %s" % path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("path must be a regular non-symlink file: %s" % path)
    if info.st_uid not in (0, os.geteuid()):
        fail("security-sensitive file has an unexpected owner: %s" % path)
    if stat.S_IMODE(info.st_mode) & 0o022:
        fail("security-sensitive file is group/world writable: %s" % path)
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        fail("private file has group/world permissions: %s" % path)
    if info.st_size > max_bytes:
        fail("file exceeds reconciliation size limit: %s" % path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks = []
        remaining = info.st_size + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            fail("file exceeds reconciliation size limit: %s" % path)
        return data
    finally:
        os.close(fd)


def canonical_statement(artifact):
    core = {key: artifact[key] for key in artifact if key != "approvals"}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode()


def verify_approvals(artifact, policy, keygen):
    operators = policy.get("operators") if isinstance(policy, dict) else None
    if not isinstance(operators, list):
        fail("approval policy operators are missing")
    allowed = {}
    for item in operators:
        if not isinstance(item, dict):
            fail("approval policy operator is invalid")
        operator_id = item.get("operator_id")
        pubkey_file = item.get("pubkey_file")
        if (
            not isinstance(operator_id, str)
            or not operator_id
            or operator_id in allowed
            or not isinstance(pubkey_file, str)
        ):
            fail("approval policy operator identity/path is invalid or duplicate")
        regular_bytes(os.path.abspath(pubkey_file))
        allowed[operator_id] = os.path.abspath(pubkey_file)
    approvals = artifact.get("approvals")
    if not isinstance(approvals, list) or len(approvals) < 2:
        fail("at least two operator approvals are required")
    statement = canonical_statement(artifact)
    statement_sha = hashlib.sha256(statement).hexdigest()
    seen = set()
    with tempfile.TemporaryDirectory(prefix="mint-reconcile-approve-") as td:
        message = os.path.join(td, "statement.json")
        with open(message, "wb") as output:
            output.write(statement)
        for index, approval in enumerate(approvals):
            if not isinstance(approval, dict):
                fail("approval %d is invalid" % index)
            operator_id = approval.get("operator_id")
            if operator_id in seen or operator_id not in allowed:
                fail("approval operator is unknown or duplicated")
            if approval.get("statement_sha256") != statement_sha:
                fail("approval is not bound to this reconciliation statement")
            signature_hex = approval.get("signature_hex")
            if (
                not isinstance(signature_hex, str)
                or not signature_hex
                or len(signature_hex) % 2
                or not re.fullmatch(r"[0-9a-f]+", signature_hex)
            ):
                fail("approval signature is malformed")
            signature = os.path.join(td, "approval-%d.sig" % index)
            with open(signature, "wb") as output:
                output.write(bytes.fromhex(signature_hex))
            run = subprocess.run(
                [keygen, "verify-release", "@" + allowed[operator_id], message, signature],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if run.returncode != 0:
                fail("operator approval signature is invalid: %s" % operator_id)
            seen.add(operator_id)
    if len(seen) < 2:
        fail("two distinct valid operator approvals are required")
    return sorted(seen), statement_sha


def bounded_uint(value, field, positive=False):
    return signer._accounting_sats(value, field, allow_zero=not positive)


def validate_evidence(artifact, old_sha, old_state, approval_policy_sha=None):
    if artifact.get("version") != ARTIFACT_VERSION or artifact.get("kind") != ARTIFACT_KIND:
        fail("reconciliation artifact kind/version is invalid")
    if artifact.get("old_state_sha256") != old_sha:
        fail("artifact is not bound to the exact old signer-state bytes")
    if (
        approval_policy_sha is not None
        and artifact.get("approval_policy_sha256") != approval_policy_sha
    ):
        fail("artifact is not bound to the pinned operator approval policy")
    if "mint_accounting" in old_state:
        fail("this tool accepts only pre-accounting legacy state")
    tip = artifact.get("canonical_tip")
    if not isinstance(tip, dict):
        fail("canonical_tip evidence is missing")
    tip_height = bounded_uint(tip.get("height"), "canonical tip height")
    tip_hash = tip.get("hash")
    if not isinstance(tip_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", tip_hash):
        fail("canonical tip hash is malformed")
    supply = bounded_uint(artifact.get("supply_sats"), "supply_sats")
    custody = bounded_uint(artifact.get("custody_sats"), "custody_sats")
    margin = bounded_uint(artifact.get("margin_sats"), "margin_sats")
    if custody < supply + margin:
        fail("inventory is insolvent")
    wait = artifact.get("wait_evidence")
    if not isinstance(wait, dict):
        fail("wait_evidence is missing")
    required_true = (
        "signer_halted",
        "minter_halted",
        "mint_mempool_empty",
        "minter_queue_empty",
        "witness_restore_halt_armed",
    )
    if any(wait.get(key) is not True for key in required_true):
        fail("quiescence/HALT evidence is incomplete")
    start = bounded_uint(wait.get("quiesced_height"), "quiesced_height")
    observed = bounded_uint(wait.get("observed_height"), "observed_height")
    if observed != tip_height or observed - start <= signer.MAX_REORG_DEPTH:
        fail("reconciliation did not wait strictly beyond MAX_REORG_DEPTH")
    if wait.get("observed_tip_hash") != tip_hash:
        fail("wait evidence tip hash differs from canonical inventory")
    return tip_height, tip_hash, supply, custody, margin


def transform(old_state, artifact, artifact_sha, operator_ids, inventory):
    legacy_entries = signer._legacy_pending_entries(old_state)
    total_signed = old_state.get("total_signed")
    if legacy_entries and total_signed is None:
        fail("legacy journal has rows but no lifetime total; reconciliation is incomplete")
    total_signed = bounded_uint(total_signed or 0, "legacy total_signed")
    tip_height, tip_hash, supply, custody, margin = inventory
    retained_total = sum(item["sats"] for item in legacy_entries)
    legacy_floor = max(0, total_signed - supply)
    extra_floor = max(0, legacy_floor - retained_total)

    rows = artifact.get("resolved_requests")
    if not isinstance(rows, list) or len(rows) != len(legacy_entries):
        fail("resolved_requests must cover every retained legacy journal row exactly")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("request_id") in by_id:
            fail("resolved request row is invalid or duplicate")
        by_id[row.get("request_id")] = row
    tombstones = []
    for entry in legacy_entries:
        row = by_id.get(entry["request_id"])
        if row is None or row.get("sats") != entry["sats"]:
            fail("resolved inventory does not match a retained legacy row")
        disposition = row.get("disposition")
        if disposition == "canonical_final":
            txid = row.get("txid")
            block_hash = row.get("block_hash")
            block_height = bounded_uint(row.get("block_height"), "resolved block_height")
            if (
                not isinstance(txid, str)
                or not re.fullmatch(r"[0-9a-f]{64}", txid)
                or not isinstance(block_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", block_hash)
                or tip_height - block_height <= signer.MAX_REORG_DEPTH
            ):
                fail("canonical_final row lacks >MAX_REORG_DEPTH block evidence")
        elif disposition == "provably_invalidated":
            evidence = row.get("invalidation_evidence_sha256")
            if not isinstance(evidence, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence):
                fail("invalidated row lacks hashed external evidence")
        else:
            fail(
                "every legacy request must be final or provably invalidated; unresolved rows pause"
            )
        tombstone = dict(entry)
        tombstone.update(row)
        tombstones.append(tombstone)
    if set(by_id) != {item["request_id"] for item in legacy_entries}:
        fail("resolved inventory contains unknown legacy request IDs")

    floor = artifact.get("omitted_journal_floor")
    if not isinstance(floor, dict) or floor.get("sats") != extra_floor:
        fail("omitted journal floor does not match conservative legacy calculation")
    if extra_floor:
        if (
            floor.get("disposition") != "resolved_inventory"
            or not isinstance(floor.get("evidence_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", floor["evidence_sha256"])
        ):
            fail("omitted legacy floor lacks two-approved inventory evidence")

    result = {
        key: value
        for key, value in old_state.items()
        if key not in ("signed", "total_signed", "mint_accounting")
    }
    result["signed"] = []
    result["mint_accounting"] = {
        "version": signer.MINT_ACCOUNTING_VERSION,
        "pending": [],
        "confirmed": [],
    }
    result["legacy_reconciliation"] = {
        "version": ARTIFACT_VERSION,
        "old_state_sha256": artifact["old_state_sha256"],
        "artifact_sha256": artifact_sha,
        "canonical_tip": {"height": tip_height, "hash": tip_hash},
        "supply_sats": supply,
        "custody_sats": custody,
        "margin_sats": margin,
        "operator_ids": operator_ids,
        "resolved_tombstones": tombstones,
        "omitted_journal_floor_tombstone": floor,
        "completed_at": int(time.time()),
    }
    return result


def atomic_apply(state_path, old_bytes, new_state):
    directory = os.path.dirname(state_path)
    halt = os.path.join(directory, "HALT")
    regular_bytes(halt)
    old_sha = hashlib.sha256(old_bytes).hexdigest()
    backup = state_path + ".pre-reconciliation." + old_sha + ".json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(backup, flags, 0o600)
    try:
        os.write(fd, old_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    fd, tmp = tempfile.mkstemp(prefix="signer-state.reconciled.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(new_state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if hashlib.sha256(regular_bytes(state_path, private=True)).hexdigest() != old_sha:
            fail("signer state changed during offline reconciliation")
        os.replace(tmp, state_path)
        tmp = None
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    return backup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--approval-policy", required=True)
    parser.add_argument("--keygen", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    state_path = os.path.abspath(args.state)
    old_bytes = regular_bytes(state_path, private=True)
    artifact_bytes = regular_bytes(os.path.abspath(args.artifact))
    policy_bytes = regular_bytes(os.path.abspath(args.approval_policy))
    old_state = json.loads(old_bytes)
    artifact = json.loads(artifact_bytes)
    policy = json.loads(policy_bytes)
    old_sha = hashlib.sha256(old_bytes).hexdigest()
    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    inventory = validate_evidence(artifact, old_sha, old_state, approval_policy_sha=policy_sha)
    operators, ignored_statement_sha = verify_approvals(
        artifact, policy, os.path.abspath(args.keygen)
    )
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    result = transform(old_state, artifact, artifact_sha, operators, inventory)
    if args.apply:
        backup = atomic_apply(state_path, old_bytes, result)
        print(
            json.dumps(
                {"status": "APPLIED", "backup": backup, "artifact_sha256": artifact_sha},
                sort_keys=True,
            )
        )
    else:
        print(
            json.dumps(
                {"status": "VALID", "artifact_sha256": artifact_sha, "new_state": result},
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stderr.write("reconcile_mint_state REFUSE: %s\n" % error)
        raise SystemExit(2)
