#!/usr/bin/env python3
"""Fail-closed reconciliation for a restored mint-reservation witness ledger.

The shared witness ledger is monotonic safety state: restoring an older backup
must never erase a reservation and silently recreate mint headroom.  This
offline command unions the restored ledger with every active/retired signer
state, verifies each witness receipt and signed-transaction binding, and keeps
every non-final reservation charged.  Only reservations proven canonical more
than MAX_REORG_DEPTH below one coherent tip may be marked final.

Apply requires the live WITNESS_RECONCILIATION_REQUIRED marker and two distinct
cryptographic operator approvals over the exact review artifact.  The restored
ledger is retained byte-for-byte before the atomic replacement, and the HALT
marker is cleared only by renaming it to an artifact-bound audit marker.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reconcile_mint_state as legacy_reconcile  # noqa: E402
import veld_peg_solvency as sol  # noqa: E402
import veld_signerd as signerd  # noqa: E402
import veld_wt_reserve as witness  # noqa: E402

ARTIFACT_VERSION = 2
ARTIFACT_KIND = "VELD_WITNESS_RESTORE_RECONCILIATION"


def fail(message):
    raise RuntimeError(str(message))


def _secure_program(path):
    path = os.path.abspath(path)
    try:
        info = os.lstat(path)
    except OSError as error:
        fail("keygen unavailable: %s" % error)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("keygen must be a regular non-symlink file")
    if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & 0o022:
        fail("keygen must be root/service-owned and not group/world writable")
    if not info.st_mode & stat.S_IXUSR:
        fail("keygen is not owner-executable")
    return path


def _json_bytes(path, private=False):
    data = legacy_reconcile.regular_bytes(
        os.path.abspath(path), private=private, max_bytes=64 * 1024 * 1024)
    try:
        value = json.loads(data)
    except Exception as error:
        fail("invalid JSON in %s: %s" % (path, error))
    return data, value


def _verify_receipt(receipt, keygen, pubkey):
    ok, why = sol.validate_reservation_receipt(receipt)
    if not ok:
        fail("invalid reservation receipt: " + why)
    with tempfile.TemporaryDirectory(prefix="witness-restore-receipt-") as td:
        message = os.path.join(td, "receipt.json")
        signature = os.path.join(td, "receipt.sig")
        with open(message, "wb") as output:
            output.write(sol.canonical_reservation_bytes(receipt))
        with open(signature, "wb") as output:
            output.write(bytes.fromhex(receipt["sig"]))
        run = subprocess.run(
            [keygen, "verify-release", "@" + pubkey, message, signature],
            capture_output=True, text=True, timeout=30)
    if run.returncode != 0:
        fail("reservation receipt signature is invalid")


def _receipt_identity(receipt):
    return tuple(receipt[field] for field in (
        "issuer_id", "witness_id", "request_id", "unsigned_tx_sha256",
        "reservation_id", "sats", "recipient", "allocation_verified",
        "allocation_request_id", "allocation_descriptor_index",
        "allocation_btc_address", "allocation_script_pubkey",
        "deposit_outpoint"))


def _merge_source(inventory, receipt, keygen, pubkey, source,
                  txid=None, signed_digest=None):
    _verify_receipt(receipt, keygen, pubkey)
    rid = receipt["reservation_id"]
    entry = inventory.get(rid)
    if entry is None:
        entry = {"receipt": copy.deepcopy(receipt), "sources": [source]}
        inventory[rid] = entry
    else:
        if _receipt_identity(entry["receipt"]) != _receipt_identity(receipt):
            fail("reservation_id has conflicting immutable receipt fields")
        entry["sources"].append(source)
        # Idempotent re-reserves legitimately refresh the beat and signature.
        # Retain the newest valid receipt while never changing its identity.
        current_rank = (entry["receipt"]["beat_seq"],
                        entry["receipt"]["reserved_at"])
        candidate_rank = (receipt["beat_seq"], receipt["reserved_at"])
        if candidate_rank > current_rank:
            entry["receipt"] = copy.deepcopy(receipt)
    if txid is not None:
        if (not isinstance(txid, str) or not sol.HASH256_RE.fullmatch(txid) or
                not isinstance(signed_digest, str) or
                not sol.HASH256_RE.fullmatch(signed_digest)):
            fail("committed source has malformed txid/digest")
        if entry.get("txid") not in (None, txid):
            fail("one reservation is bound to conflicting signed txids")
        if entry.get("signed_tx_sha256") not in (None, signed_digest):
            fail("one reservation is bound to conflicting signed bytes")
        entry["txid"] = txid
        entry["signed_tx_sha256"] = signed_digest
    return entry


def _signed_binding(record, receipt):
    signed_hex = record.get("signed_tx_hex")
    if not isinstance(signed_hex, str):
        fail("signed audit record with a witness receipt lacks signed_tx_hex")
    try:
        signed_bytes = bytes.fromhex(signed_hex)
        unsigned_hex = sol.unsigned_template_from_signed_hex(signed_hex)
    except Exception as error:
        fail("signed audit transaction is malformed: %s" % error)
    unsigned_sha = hashlib.sha256(bytes.fromhex(unsigned_hex)).hexdigest()
    if unsigned_sha != receipt["unsigned_tx_sha256"]:
        fail("signed audit transaction does not bind its witness receipt")
    txid = hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest()
    if record.get("txid") != txid:
        fail("signed audit txid differs from exact signed bytes")
    return txid, hashlib.sha256(signed_bytes).hexdigest()


def validate_receipt_archive(archive):
    """Validate either an aggregate archive or one exact WORM terminal object."""
    if (isinstance(archive, dict) and archive.get("version") == 1 and
            archive.get("kind") == "VELD_MINT_RECEIPT_ARCHIVE" and
            set(archive) == {"version", "kind", "entries"} and
            isinstance(archive["entries"], list)):
        for index, entry in enumerate(archive["entries"]):
            if (not isinstance(entry, dict) or
                    set(entry) not in ({"receipt"},
                                       {"receipt", "signed_tx_hex", "txid"})):
                fail("receipt archive entry %d has invalid fields" % index)
        return archive
    required = {"version", "kind", "receipt", "txid", "signed_tx_sha256",
                "block_height", "block_hash", "finalized_at_tip",
                "finalized_at_tip_hash"}
    if (not isinstance(archive, dict) or set(archive) != required or
            archive.get("version") != witness.TERMINAL_ARCHIVE_VERSION or
            archive.get("kind") != witness.TERMINAL_ARCHIVE_KIND):
        fail("receipt archive schema is invalid")
    receipt = archive.get("receipt")
    ok, why = sol.validate_reservation_receipt(receipt)
    if not ok:
        fail("terminal receipt archive is invalid: " + why)
    for field in ("txid", "signed_tx_sha256", "block_hash",
                  "finalized_at_tip_hash"):
        if not isinstance(archive.get(field), str) or not sol.HASH256_RE.fullmatch(
                archive[field]):
            fail("terminal receipt archive %s is malformed" % field)
    height = archive.get("block_height")
    tip = archive.get("finalized_at_tip")
    if (type(height) is not int or type(tip) is not int or height < 0 or
            tip < height or tip - height + 1 <= witness.MAX_REORG_DEPTH):
        fail("terminal receipt archive lacks >MAX_REORG_DEPTH evidence")
    return archive


def validate_terminal_log_bytes(data):
    if not isinstance(data, bytes) or not data.endswith(b"\n"):
        fail("restored terminal tombstone log has a partial tail")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("restored terminal tombstone log is not UTF-8")
    if not lines:
        fail("restored terminal tombstone log is empty")
    try:
        header = witness.strict_json_loads(
            lines[0].encode("utf-8"), "restored terminal tombstone header")
    except Exception as error:
        fail("restored terminal tombstone header is invalid: %s" % error)
    if header != witness.TERMINAL_LOG_HEADER:
        fail("restored terminal tombstone header is invalid")
    result = []
    previous = witness.ZERO_HASH
    for sequence, line in enumerate(lines[1:], 1):
        if len(line.encode("utf-8")) > 16 * 1024:
            fail("restored terminal tombstone row is oversized")
        try:
            record = witness.strict_json_loads(
                line.encode("utf-8"), "restored terminal tombstone")
            witness._validate_tombstone(record, sequence, previous)
        except SystemExit:
            fail("restored terminal tombstone row is invalid")
        except Exception as error:
            fail("restored terminal tombstone row is invalid: %s" % error)
        result.append(record)
        previous = record["record_sha256"]
    return result


def collect_inventory(restored_ledger, signer_states, keygen, pubkey,
                      ledger_snapshots=None, receipt_archives=None,
                      terminal_tombstones=None):
    inventory = {}
    request_ids = {}
    deposit_outpoints = {}
    allocation_requests = {}
    ledgers = [("restored-ledger", restored_ledger)]
    ledgers.extend(ledger_snapshots or [])
    for ledger_id, ledger in ledgers:
        validate_restored_ledger(ledger)
        for index, item in enumerate(ledger.get("reservations", [])):
            receipt = item["receipt"]
            txid = item.get("txid")
            digest = item.get("signed_tx_sha256")
            _merge_source(inventory, receipt, keygen, pubkey,
                          "%s:%d" % (ledger_id, index), txid, digest)

    for signer_id, state in signer_states:
        if not isinstance(state, dict):
            fail("signer state %s is not an object" % signer_id)
        try:
            normalized = copy.deepcopy(state)
            accounting, ignored_migrated = signerd._initialize_mint_accounting(normalized)
        except Exception as error:
            fail("signer state %s is not current/reconciled: %s" %
                 (signer_id, error))
        signed_by_request = {}
        signed = normalized.get("signed")
        if not isinstance(signed, list):
            fail("signer state %s signed journal is invalid" % signer_id)
        for index, record in enumerate(signed):
            if not isinstance(record, dict):
                fail("signer state %s signed row is invalid" % signer_id)
            request_id = record.get("request_id")
            if request_id in signed_by_request:
                fail("signer state %s has duplicate signed request_id" % signer_id)
            receipt = record.get("witness_receipt")
            if receipt is None:
                fail("signer state %s contains a pre-witness signature" % signer_id)
            if (receipt.get("request_id") != request_id or
                    receipt.get("sats") != record.get("sats") or
                    receipt.get("recipient") != record.get("to")):
                fail("signed audit fields differ from witness receipt")
            txid, digest = _signed_binding(record, receipt)
            _merge_source(inventory, receipt, keygen, pubkey,
                          "%s:signed:%d" % (signer_id, index), txid, digest)
            signed_by_request[request_id] = (txid, digest)

        for field in ("pending", "confirmed"):
            for index, row in enumerate(accounting[field]):
                receipt = row.get("witness_receipt")
                if receipt is None:
                    fail("signer state %s has an unwitnessed outstanding mint" % signer_id)
                if receipt["request_id"] != row["request_id"]:
                    fail("accounting request differs from witness receipt")
                entry = _merge_source(
                    inventory, receipt, keygen, pubkey,
                    "%s:%s:%d" % (signer_id, field, index))
                claimed_txid = row.get("txid")
                if claimed_txid is not None:
                    binding = signed_by_request.get(row["request_id"])
                    if binding is None or binding[0] != claimed_txid:
                        # A restored witness ledger can independently supply the
                        # exact digest, but an accounting-only txid is not enough.
                        if entry.get("txid") != claimed_txid:
                            fail("accounting txid lacks exact signed-byte evidence")

    terminal_archive_digests = {}
    for archive_id, archive in (receipt_archives or []):
        validate_receipt_archive(archive)
        if archive.get("kind") == witness.TERMINAL_ARCHIVE_KIND:
            digest = hashlib.sha256(
                witness._canonical_json_bytes(archive)).hexdigest()
            rid = archive["receipt"]["reservation_id"]
            if rid in terminal_archive_digests and terminal_archive_digests[rid] != digest:
                fail("one terminal reservation has conflicting WORM archives")
            terminal_archive_digests[rid] = digest
            merged = _merge_source(
                inventory, archive["receipt"], keygen, pubkey,
                "%s:terminal" % archive_id, archive["txid"],
                archive["signed_tx_sha256"])
            # The tombstone hashes one exact signed receipt envelope, not merely
            # its stable identity. Preserve the digest-bound WORM copy even if a
            # signer journal carries another valid idempotent beat refresh.
            merged["receipt"] = copy.deepcopy(archive["receipt"])
            continue
        for index, item in enumerate(archive["entries"]):
            receipt = item["receipt"]
            txid = digest = None
            if "signed_tx_hex" in item:
                txid, digest = _signed_binding(item, receipt)
            _merge_source(inventory, receipt, keygen, pubkey,
                          "%s:%d" % (archive_id, index), txid, digest)

    for index, tombstone in enumerate(terminal_tombstones or []):
        rid = tombstone["reservation_id"]
        entry = inventory.get(rid)
        if entry is None:
            fail("terminal tombstone lacks its full receipt archive/inventory")
        receipt = entry["receipt"]
        if (_receipt_identity(receipt) != tuple(
                tombstone[field] for field in witness.TOMBSTONE_IDENTITY_FIELDS) or
                witness._receipt_full_sha256(receipt) != tombstone["receipt_sha256"]):
            fail("terminal tombstone differs from its exact full receipt")
        if (entry.get("txid") != tombstone["txid"] or
                entry.get("signed_tx_sha256") != tombstone["signed_tx_sha256"]):
            fail("terminal tombstone differs from committed signed-byte evidence")
        if terminal_archive_digests.get(rid) != tombstone["archive_entry_sha256"]:
            fail("terminal tombstone lacks its exact digest-bound WORM archive")
        entry["tombstone"] = copy.deepcopy(tombstone)
        entry["sources"].append("restored-terminal:%d" % index)

    for rid, entry in inventory.items():
        receipt = entry["receipt"]
        request_id = receipt["request_id"]
        if request_id in request_ids and request_ids[request_id] != rid:
            fail("request_id maps to multiple reservation identities")
        request_ids[request_id] = rid
        if receipt.get("allocation_verified") is True:
            outpoint = receipt["deposit_outpoint"]
            allocation_request = receipt["allocation_request_id"]
            if outpoint in deposit_outpoints and deposit_outpoints[outpoint] != rid:
                fail("Bitcoin deposit outpoint maps to multiple reservation identities")
            if (allocation_request in allocation_requests and
                    allocation_requests[allocation_request] != rid):
                fail("wrap allocation maps to multiple reservation identities")
            deposit_outpoints[outpoint] = rid
            allocation_requests[allocation_request] = rid
    return inventory


def validate_restored_ledger(ledger):
    # Ledger v2 is accepted only by this halted, two-operator offline path.  It
    # still contains every full receipt, so normalize it into an empty v3
    # terminal checkpoint; live code never auto-creates or auto-migrates state.
    if (isinstance(ledger, dict) and ledger.get("version") == 2 and
            set(ledger) == {"version", "reservations"} and
            isinstance(ledger.get("reservations"), list)):
        ledger = {
            "version": witness.LEDGER_VERSION,
            "terminal_count": 0,
            "terminal_head_sha256": witness.ZERO_HASH,
            "reservations": copy.deepcopy(ledger["reservations"]),
        }
    if (not isinstance(ledger, dict) or
            ledger.get("version") != witness.LEDGER_VERSION or
            set(ledger) != {"version", "terminal_count",
                            "terminal_head_sha256", "reservations"} or
            type(ledger.get("terminal_count")) is not int or
            ledger["terminal_count"] < 0 or
            not isinstance(ledger.get("terminal_head_sha256"), str) or
            not sol.HASH256_RE.fullmatch(ledger["terminal_head_sha256"]) or
            not isinstance(ledger["reservations"], list)):
        fail("restored witness ledger schema is invalid")
    seen = set()
    allowed = {"receipt", "status", "txid", "block_height", "block_hash",
               "signed_tx_sha256"}
    for index, entry in enumerate(ledger["reservations"]):
        if not isinstance(entry, dict) or set(entry) - allowed:
            fail("restored witness ledger entry %d has invalid fields" % index)
        receipt = entry.get("receipt")
        ok, why = sol.validate_reservation_receipt(receipt)
        if not ok:
            fail("restored witness ledger entry %d: %s" % (index, why))
        rid = receipt["reservation_id"]
        if rid in seen:
            fail("restored witness ledger has duplicate reservation_id")
        seen.add(rid)
        status = entry.get("status")
        txid = entry.get("txid")
        if status not in ("reserved", "confirmed", "final"):
            fail("restored witness ledger status is invalid")
        if txid is not None and (not isinstance(txid, str) or
                                 not sol.HASH256_RE.fullmatch(txid)):
            fail("restored witness ledger txid is malformed")
        if txid is not None:
            digest = entry.get("signed_tx_sha256")
            if not isinstance(digest, str) or not sol.HASH256_RE.fullmatch(digest):
                fail("restored committed reservation lacks signed-byte digest")
        elif "signed_tx_sha256" in entry:
            fail("restored uncommitted reservation carries a signed-byte digest")
        if status in ("confirmed", "final"):
            if (txid is None or not isinstance(entry.get("block_height"), int) or
                    isinstance(entry.get("block_height"), bool) or
                    entry["block_height"] < 0 or
                    not isinstance(entry.get("block_hash"), str) or
                    not sol.HASH256_RE.fullmatch(entry["block_hash"])):
                fail("restored confirmed/final reservation lacks block evidence")
        elif "block_height" in entry or "block_hash" in entry:
            fail("restored reserved entry unexpectedly carries block evidence")
    return ledger


def validate_artifact(artifact, restored_sha, restored_terminal_sha,
                      signer_hashes, inventory, terminal_tombstones=None,
                      snapshot_hashes=None, archive_hashes=None,
                      approval_policy_sha=None, beat_pubkey_sha=None):
    if (not isinstance(artifact, dict) or
            artifact.get("version") != ARTIFACT_VERSION or
            artifact.get("kind") != ARTIFACT_KIND):
        fail("witness reconciliation artifact kind/version is invalid")
    if artifact.get("restored_ledger_sha256") != restored_sha:
        fail("artifact is not bound to the exact restored witness ledger")
    if artifact.get("restored_terminal_log_sha256") != restored_terminal_sha:
        fail("artifact is not bound to the exact restored terminal tombstone log")
    if (approval_policy_sha is not None and
            artifact.get("approval_policy_sha256") != approval_policy_sha):
        fail("artifact is not bound to the pinned operator approval policy")
    if (beat_pubkey_sha is not None and
            artifact.get("beat_pubkey_sha256") != beat_pubkey_sha):
        fail("artifact is not bound to the pinned beat/receipt public key")
    expected_hashes = sorted(signer_hashes)
    if (len(expected_hashes) != len(set(expected_hashes)) or
            artifact.get("signer_state_sha256s") != expected_hashes):
        fail("artifact is not bound to the exact unique signer-state inventory")
    expected_snapshots = sorted(snapshot_hashes or [])
    expected_archives = sorted(archive_hashes or [])
    if (len(expected_snapshots) != len(set(expected_snapshots)) or
            artifact.get("ledger_snapshot_sha256s") != expected_snapshots):
        fail("artifact is not bound to the exact immutable ledger snapshots")
    if (len(expected_archives) != len(set(expected_archives)) or
            artifact.get("receipt_archive_sha256s") != expected_archives):
        fail("artifact is not bound to the exact receipt archives")
    if artifact.get("source_inventory_complete") is not True:
        fail("artifact does not attest a complete active/retired signer inventory")

    tip = artifact.get("canonical_tip")
    if not isinstance(tip, dict):
        fail("canonical_tip evidence is missing")
    tip_height = signerd._accounting_sats(tip.get("height"), "canonical tip height")
    tip_hash = tip.get("hash")
    if not isinstance(tip_hash, str) or not sol.HASH256_RE.fullmatch(tip_hash):
        fail("canonical tip hash is malformed")
    supply = signerd._accounting_sats(artifact.get("supply_sats"), "supply_sats")
    custody = signerd._accounting_sats(artifact.get("custody_sats"), "custody_sats")
    margin = signerd._accounting_sats(artifact.get("margin_sats"), "margin_sats")
    if custody < supply + margin:
        fail("inventory is insolvent")
    wait = artifact.get("wait_evidence")
    required = ("signer_halted", "minter_halted", "witness_halted",
                "mint_mempool_empty", "minter_queue_empty")
    if not isinstance(wait, dict) or any(wait.get(key) is not True for key in required):
        fail("restore quiescence/HALT evidence is incomplete")
    quiesced = signerd._accounting_sats(wait.get("quiesced_height"),
                                        "quiesced_height")
    observed = signerd._accounting_sats(wait.get("observed_height"),
                                        "observed_height")
    if (observed != tip_height or
            observed - quiesced <= witness.MAX_REORG_DEPTH or
            wait.get("observed_tip_hash") != tip_hash):
        fail("restore reconciliation did not wait strictly beyond MAX_REORG_DEPTH")

    issuer_id = artifact.get("issuer_id")
    witness_id = artifact.get("witness_id")
    if (not isinstance(issuer_id, str) or not sol.IDENTIFIER_RE.fullmatch(issuer_id) or
            not isinstance(witness_id, str) or
            not sol.IDENTIFIER_RE.fullmatch(witness_id)):
        fail("artifact issuer/witness identity is invalid")
    for entry in inventory.values():
        receipt = entry["receipt"]
        if receipt["issuer_id"] != issuer_id or receipt["witness_id"] != witness_id:
            fail("receipt identity differs from restored witness policy")

    rows = artifact.get("reservations")
    if not isinstance(rows, list) or len(rows) != len(inventory):
        fail("artifact reservations must cover the exact receipt union")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("reservation_id") in by_id:
            fail("artifact reservation row is invalid/duplicate")
        by_id[row.get("reservation_id")] = row
    if set(by_id) != set(inventory):
        fail("artifact reservations differ from the exact receipt union")

    result = []
    for rid in sorted(inventory):
        source = inventory[rid]
        row = by_id[rid]
        disposition = row.get("disposition")
        output = {"receipt": source["receipt"]}
        if disposition == "outstanding":
            if source.get("tombstone") is not None:
                fail("an immutable terminal tombstone cannot be reclassified outstanding")
            if set(row) != {"reservation_id", "disposition"}:
                fail("outstanding reservation row has unexpected evidence fields")
            output["status"] = "reserved"
            if source.get("txid"):
                output["txid"] = source["txid"]
                output["signed_tx_sha256"] = source["signed_tx_sha256"]
        elif disposition == "canonical_final":
            allowed = {"reservation_id", "disposition", "txid",
                       "block_height", "block_hash"}
            if set(row) != allowed or row.get("txid") != source.get("txid"):
                fail("canonical_final reservation does not bind known signed bytes")
            height = signerd._accounting_sats(row.get("block_height"),
                                               "final block_height")
            block_hash = row.get("block_hash")
            if (not isinstance(block_hash, str) or
                    not sol.HASH256_RE.fullmatch(block_hash) or
                    tip_height - height <= witness.MAX_REORG_DEPTH):
                fail("canonical_final reservation lacks >MAX_REORG_DEPTH evidence")
            output.update({"status": "final", "txid": source["txid"],
                           "signed_tx_sha256": source["signed_tx_sha256"],
                           "block_height": height, "block_hash": block_hash})
        else:
            fail("reservation must remain outstanding or have canonical-final evidence")
        # Existing tombstones stay in their append-only chain. Newly proven final
        # rows stage in active with their full receipt; the first live call archives
        # and compacts them under the configured external/WORM hook.
        if source.get("tombstone") is None:
            result.append(output)
    terminals = terminal_tombstones or []
    return {
        "version": witness.LEDGER_VERSION,
        "terminal_count": len(terminals),
        "terminal_head_sha256": (terminals[-1]["record_sha256"]
                                 if terminals else witness.ZERO_HASH),
        "reservations": result,
    }


def _ledger_payload(ledger):
    return (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_exact_backup(path, payload):
    if os.path.exists(path):
        if legacy_reconcile.regular_bytes(
                path, private=True, max_bytes=256 * 1024 * 1024) != payload:
            fail("existing reconciliation backup differs from restored state")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                fail("reconciliation backup write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_apply_locked(paths, restored_bytes, restored_terminal_bytes,
                         reconciled, artifact_sha):
    marker = paths["restore_halt"]
    witness._secure_file(marker, exact_mode=0o600)
    ledger_path = paths["ledger"]
    restored_sha = hashlib.sha256(restored_bytes).hexdigest()
    backup = ledger_path + ".pre-reconciliation." + restored_sha + ".json"
    terminal_sha = hashlib.sha256(restored_terminal_bytes).hexdigest()
    terminal_backup = (paths["terminal"] + ".pre-reconciliation." +
                       terminal_sha + ".jsonl")
    desired = _ledger_payload(reconciled)
    current = legacy_reconcile.regular_bytes(
        ledger_path, private=True, max_bytes=64 * 1024 * 1024)
    if current not in (restored_bytes, desired):
        fail("witness ledger changed during offline reconciliation")
    current_terminal = legacy_reconcile.regular_bytes(
        paths["terminal"], private=True, max_bytes=256 * 1024 * 1024)
    if current_terminal != restored_terminal_bytes:
        fail("terminal tombstone log changed during offline reconciliation")

    _write_exact_backup(backup, restored_bytes)
    _write_exact_backup(terminal_backup, restored_terminal_bytes)
    if current == restored_bytes:
        witness.atomic_write(ledger_path, desired.decode("utf-8"))

    audit_marker = os.path.join(
        os.path.dirname(marker), "WITNESS_RECONCILED." + artifact_sha)
    if os.path.lexists(audit_marker):
        fail("artifact-bound witness reconciliation audit marker already exists")
    os.rename(marker, audit_marker)
    dfd = os.open(os.path.dirname(marker),
                  os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return backup, terminal_backup, audit_marker


def atomic_apply(paths, restored_bytes, restored_terminal_bytes,
                 reconciled, artifact_sha):
    """Apply only while holding the same lock as both live forced commands.

    Validation can be performed offline, but the final current-ledger check,
    backup, replacement, and HALT-marker transition are one serialized critical
    section.  A command that started before the HALT marker therefore either
    finishes before this lock is acquired (and changes the exact ledger hash) or
    sees the marker after it acquires the lock and refuses.
    """
    with witness.exclusive_witness_state_lock(paths):
        return _atomic_apply_locked(
            paths, restored_bytes, restored_terminal_bytes,
            reconciled, artifact_sha)


def _restored_ledger(paths, expected_sha=None):
    ledger_path = paths["ledger"]
    current = legacy_reconcile.regular_bytes(
        ledger_path, private=True, max_bytes=64 * 1024 * 1024)
    if expected_sha and hashlib.sha256(current).hexdigest() != expected_sha:
        backup = ledger_path + ".pre-reconciliation." + expected_sha + ".json"
        try:
            original = legacy_reconcile.regular_bytes(
                backup, private=True, max_bytes=64 * 1024 * 1024)
        except Exception:
            return current
        if hashlib.sha256(original).hexdigest() == expected_sha:
            return original
    return current


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--approval-policy", required=True)
    parser.add_argument("--keygen", required=True)
    parser.add_argument("--beat-pubkey", required=True)
    parser.add_argument("--signer-state", action="append", default=[], required=True,
                        help="repeat for every active and retired mint signer state")
    parser.add_argument("--ledger-snapshot", action="append", default=[],
                        help="repeat for every immutable/off-host witness-ledger snapshot")
    parser.add_argument("--receipt-archive", action="append", default=[],
                        help="repeat for every immutable VELD_MINT_RECEIPT_ARCHIVE")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    paths = witness._paths({"state_dir": os.path.abspath(args.state_dir)})
    if not os.path.lexists(paths["restore_halt"]):
        fail("WITNESS_RECONCILIATION_REQUIRED is not armed")
    witness._secure_file(paths["restore_halt"], exact_mode=0o600)
    artifact_bytes, artifact = _json_bytes(args.artifact)
    policy_bytes, policy = _json_bytes(args.approval_policy)
    keygen = _secure_program(args.keygen)
    pubkey = os.path.abspath(args.beat_pubkey)
    pubkey_bytes = legacy_reconcile.regular_bytes(pubkey)

    expected_restored_sha = (artifact.get("restored_ledger_sha256")
                             if isinstance(artifact, dict) else None)
    restored_bytes = _restored_ledger(paths, expected_restored_sha)
    restored_sha = hashlib.sha256(restored_bytes).hexdigest()
    try:
        restored_json = validate_restored_ledger(json.loads(restored_bytes))
    except RuntimeError:
        raise
    except Exception as error:
        fail("restored witness ledger is invalid: %s" % error)
    restored_terminal_bytes = legacy_reconcile.regular_bytes(
        paths["terminal"], private=True, max_bytes=256 * 1024 * 1024)
    restored_terminal_sha = hashlib.sha256(restored_terminal_bytes).hexdigest()
    terminal_tombstones = validate_terminal_log_bytes(restored_terminal_bytes)
    expected_head = (terminal_tombstones[-1]["record_sha256"]
                     if terminal_tombstones else witness.ZERO_HASH)
    if (restored_json["terminal_count"] != len(terminal_tombstones) or
            restored_json["terminal_head_sha256"] != expected_head):
        fail("restored active snapshot does not checkpoint its exact terminal log")

    signer_states = []
    signer_hashes = []
    seen_paths = set()
    for index, path in enumerate(args.signer_state):
        path = os.path.abspath(path)
        if path in seen_paths:
            fail("duplicate signer-state path")
        seen_paths.add(path)
        data, state = _json_bytes(path, private=True)
        signer_states.append(("signer-%d" % index, state))
        signer_hashes.append(hashlib.sha256(data).hexdigest())

    ledger_snapshots = []
    snapshot_hashes = []
    for index, path in enumerate(args.ledger_snapshot):
        data, snapshot = _json_bytes(path, private=True)
        ledger_snapshots.append((
            "ledger-snapshot-%d" % index, validate_restored_ledger(snapshot)))
        snapshot_hashes.append(hashlib.sha256(data).hexdigest())
    receipt_archives = []
    archive_hashes = []
    for index, path in enumerate(args.receipt_archive):
        data, archive = _json_bytes(path, private=True)
        receipt_archives.append((
            "receipt-archive-%d" % index, validate_receipt_archive(archive)))
        archive_hashes.append(hashlib.sha256(data).hexdigest())

    inventory = collect_inventory(
        restored_json, signer_states, keygen, pubkey,
        ledger_snapshots=ledger_snapshots, receipt_archives=receipt_archives,
        terminal_tombstones=terminal_tombstones)
    reconciled = validate_artifact(
        artifact, restored_sha, restored_terminal_sha,
        signer_hashes, inventory, terminal_tombstones,
        snapshot_hashes=snapshot_hashes, archive_hashes=archive_hashes,
        approval_policy_sha=hashlib.sha256(policy_bytes).hexdigest(),
        beat_pubkey_sha=hashlib.sha256(pubkey_bytes).hexdigest())
    operators, statement_sha = legacy_reconcile.verify_approvals(
        artifact, policy, keygen)
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    answer = {"status": "VALID", "artifact_sha256": artifact_sha,
              "statement_sha256": statement_sha, "operator_ids": operators,
              "reservation_count": len(inventory),
              "active_reservation_count": len(reconciled["reservations"]),
              "terminal_reservation_count": len(terminal_tombstones),
              "reconciled_ledger": reconciled}
    if args.apply:
        backup, terminal_backup, audit_marker = atomic_apply(
            paths, restored_bytes, restored_terminal_bytes,
            reconciled, artifact_sha)
        answer.update({"status": "APPLIED", "backup": backup,
                       "terminal_backup": terminal_backup,
                       "audit_marker": audit_marker})
    print(json.dumps(answer, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as error:
        sys.stderr.write("reconcile_witness_restore REFUSE: %s\n" % error)
        raise SystemExit(2)
