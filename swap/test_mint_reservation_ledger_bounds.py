#!/usr/bin/env python3
"""Adversarial qualification for bounded witness authorization state."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import veld_peg_solvency as sol
import veld_wt_reserve as witness
import reconcile_witness_restore as restore


ISSUER = "Vissuer"
RECIPIENT = "Vrecipient"
TIP_HASH = "11" * 32
BLOCK_HASH = "22" * 32


def unsigned_tx(tag=1):
    return (
        b"\x01\x00\x00\x00"
        + b"\x01"
        + bytes([tag]) * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + (1000).to_bytes(8, "little")
        + b"\x02\x6a\x00"
        + b"\x00\x00\x00\x00"
    ).hex()


def signed_tx(unsigned_hex):
    raw = bytearray.fromhex(unsigned_hex)
    raw[41:42] = b"\x01\x01"
    return bytes(raw).hex()


def receipt(tag=1, signature_bytes=7000):
    unsigned = unsigned_tx(tag)
    request_id = hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
    return {
        "v": sol.RESERVATION_VERSION,
        "kind": sol.RESERVATION_KIND,
        "issuer_id": ISSUER,
        "witness_id": "witness-1",
        "request_id": request_id,
        "unsigned_tx_sha256": request_id,
        "reservation_id": sol.reservation_id(
            ISSUER, request_id, request_id, 1, RECIPIENT, None, None
        ),
        "sats": 1,
        "recipient": RECIPIENT,
        "beat_seq": 1,
        "tip": 100,
        "tip_hash": TIP_HASH,
        "headroom_sats": 1000,
        "reserved_at": 1,
        "allocation_verified": False,
        "allocation_request_id": None,
        "allocation_descriptor_index": None,
        "allocation_btc_address": None,
        "allocation_script_pubkey": None,
        "deposit_outpoint": None,
        "sig_alg": "mldsa65",
        "sig": "ab" * signature_bytes,
    }


def c1_receipt(signature_bytes=7000):
    unsigned = unsigned_tx(9)
    request_id = hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
    allocation_id = "0" * 31 + "1"
    outpoint = "44" * 32 + ":0"
    return {
        "v": sol.C1_RESERVATION_VERSION,
        "kind": sol.RESERVATION_KIND,
        "issuer_id": ISSUER,
        "witness_id": "witness-1",
        "request_id": request_id,
        "unsigned_tx_sha256": request_id,
        "reservation_id": sol.reservation_id(
            ISSUER, request_id, request_id, 10_000, RECIPIENT, outpoint, allocation_id
        ),
        "sats": 10_000,
        "recipient": RECIPIENT,
        "beat_seq": 9,
        "tip": 100,
        "tip_hash": TIP_HASH,
        "headroom_sats": 100_000_000,
        "reserved_at": 1,
        "allocation_verified": True,
        "allocation_request_id": allocation_id,
        "allocation_descriptor_index": 1000,
        "allocation_btc_address": "bc1p" + "q" * 58,
        "allocation_script_pubkey": "5120" + "ab" * 32,
        "deposit_outpoint": outpoint,
        "allocation_capacity_policy_sha256": "55" * 32,
        "allocation_public_descriptor_range_start": 1000,
        "allocation_public_descriptor_range_end": 10999,
        "sig_alg": "mldsa65",
        "sig": "ab" * signature_bytes,
    }


class FakeRpc:
    def __init__(self, txid, tip=199, height=99):
        self.txid = txid
        self.tip = tip
        self.height = height

    def call(self, method, params=None):
        if method == "getrawtransaction":
            if params[0] != self.txid:
                raise RuntimeError("unknown transaction")
            return {
                "txid": self.txid,
                "confirmations": self.tip - self.height + 1,
                "block_height": self.height,
                "block_hash": BLOCK_HASH,
            }
        if method == "getblockhash":
            return BLOCK_HASH if params[0] == self.height else TIP_HASH
        raise AssertionError(method)


class ReservationLedgerBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="witness-ledger-v3-")
        self.state = Path(self.temp.name) / "state"
        self.state.mkdir(mode=0o700)
        self.cfg = {
            "issuer_id": ISSUER,
            "witness_id": "witness-1",
            "issuer_p2pkh_hex": "76a914" + "33" * 20 + "88ac",
            "state_dir": str(self.state),
            "reservation_ledger": {
                "max_active_rows": 4,
                "max_active_bytes": 64 * 1024,
                "max_terminal_rows": 4,
                "max_terminal_bytes": 64 * 1024,
                "min_free_bytes": 16 * 1024 * 1024,
                "terminal_archive_command": ["/archive-hook"],
            },
        }
        self.paths = witness._paths(self.cfg)
        witness.atomic_write(
            self.paths["ledger"],
            json.dumps(witness._empty_ledger(), sort_keys=True, separators=(",", ":")) + "\n",
        )
        witness.atomic_write(self.paths["terminal"], witness._empty_terminal_log_text())
        self.receipt = receipt()
        self.signed = signed_tx(unsigned_tx())
        signed_bytes = bytes.fromhex(self.signed)
        self.txid = hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest()
        self.signed_digest = hashlib.sha256(signed_bytes).hexdigest()
        ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
        ledger["reservations"].append(
            {
                "receipt": self.receipt,
                "status": "reserved",
                "txid": self.txid,
                "signed_tx_sha256": self.signed_digest,
            }
        )
        witness._persist_ledger(self.paths, ledger, witness._reservation_ledger_policy(self.cfg))

    def tearDown(self):
        self.temp.cleanup()

    def beat(self, tip):
        return sol.stamp_heartbeat(
            sol.build_beat_payload(1000, 0, 0, tip, TIP_HASH, tip, 120), int(time.time())
        )

    def test_strict_depth_archive_then_compact_and_terminal_commit_replay(self):
        ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
        with mock.patch.object(witness, "_archive_terminal") as archive:
            # Exactly 100 confirmations is still reorg-protected active state.
            self.assertEqual(
                witness._reconcile(
                    ledger, self.beat(198), FakeRpc(self.txid, tip=198), self.cfg, self.paths
                ),
                0,
            )
            self.assertEqual(ledger["reservations"][0]["status"], "confirmed")
            archive.assert_not_called()

            # Strictly deeper than 100 is archived before receipt compaction.
            self.assertEqual(
                witness._reconcile(
                    ledger, self.beat(199), FakeRpc(self.txid), self.cfg, self.paths
                ),
                0,
            )
            archive.assert_called_once()
            archived = archive.call_args.args[0]
            self.assertEqual(archived["receipt"]["sig"], self.receipt["sig"])

        restarted = witness._load_ledger(self.paths["ledger"], self.cfg)
        self.assertEqual(restarted["reservations"], [])
        self.assertEqual(restarted["terminal_count"], 1)
        self.assertNotIn(self.receipt["sig"], Path(self.paths["ledger"]).read_text())
        self.assertLess(Path(self.paths["terminal"]).stat().st_size, len(self.receipt["sig"]) // 2)

        decoded = mock.Mock(
            returncode=0, stdout=json.dumps({"from": ISSUER, "to": RECIPIENT, "sats": 1}), stderr=""
        )
        with mock.patch.object(witness.subprocess, "run", return_value=decoded):
            answer = witness.handle_commit(
                {
                    "reservation_id": self.receipt["reservation_id"],
                    "txid": self.txid,
                    "signed_tx_hex": self.signed,
                },
                self.cfg,
                self.paths,
                restarted,
            )
        self.assertTrue(answer["terminal"])
        mutated = self.signed[:-2] + ("00" if self.signed[-2:] != "00" else "01")
        with (
            mock.patch.object(witness.subprocess, "run", return_value=decoded),
            self.assertRaises(SystemExit),
        ):
            witness.handle_commit(
                {
                    "reservation_id": self.receipt["reservation_id"],
                    "txid": hashlib.sha256(
                        hashlib.sha256(bytes.fromhex(mutated)).digest()
                    ).hexdigest(),
                    "signed_tx_hex": mutated,
                },
                self.cfg,
                self.paths,
                restarted,
            )

    def test_c1_deep_terminal_worm_archive_removes_local_row_without_tombstone(self):
        c1 = c1_receipt()
        signed = signed_tx(unsigned_tx(9))
        signed_bytes = bytes.fromhex(signed)
        entry = {
            "receipt": c1,
            "status": "final",
            "txid": hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest(),
            "signed_tx_sha256": hashlib.sha256(signed_bytes).hexdigest(),
            "block_height": 99,
            "block_hash": BLOCK_HASH,
        }
        ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
        ledger["reservations"] = [entry]
        witness._persist_ledger(self.paths, ledger, witness._reservation_ledger_policy(self.cfg))

        # Exactly 100 confirmations can neither archive nor delete authority.
        with (
            mock.patch.object(witness, "_archive_terminal") as archive,
            self.assertRaises(SystemExit),
        ):
            witness._compact_terminal(self.paths, ledger, entry, self.beat(198), self.cfg)
        archive.assert_not_called()
        self.assertEqual(len(ledger["reservations"]), 1)

        # At 101, the complete receipt reaches WORM before the local active body
        # is atomically removed. Consensus is the lifetime C1 replay authority,
        # so no per-allocation local tombstone remains.
        with mock.patch.object(witness, "_archive_terminal") as archive:
            witness._compact_terminal(self.paths, ledger, entry, self.beat(199), self.cfg)
        archive.assert_called_once()
        archived = archive.call_args.args[0]
        self.assertIs(restore.validate_receipt_archive(archived), archived)
        self.assertEqual(archived["receipt"], c1)
        restarted = witness._load_ledger(self.paths["ledger"], self.cfg)
        self.assertEqual(restarted["reservations"], [])
        self.assertEqual(restarted["terminal_count"], 0)
        self.assertEqual(
            Path(self.paths["terminal"]).read_text(), witness._empty_terminal_log_text()
        )
        self.assertNotIn(c1["sig"], Path(self.paths["ledger"]).read_text())

        # Post-compaction exact recovery comes from the digest-bound WORM
        # object. The local witness cannot accidentally recreate/re-sign it.
        decoded = mock.Mock(
            returncode=0,
            stdout=json.dumps({"from": ISSUER, "to": RECIPIENT, "sats": 10_000}),
            stderr="",
        )
        with (
            mock.patch.object(witness.subprocess, "run", return_value=decoded),
            self.assertRaises(SystemExit),
        ):
            witness.handle_commit(
                {
                    "reservation_id": c1["reservation_id"],
                    "txid": entry["txid"],
                    "signed_tx_hex": signed,
                },
                self.cfg,
                self.paths,
                restarted,
            )

    def test_production_capacity_covers_9999_10000_and_rejects_10001(self):
        policy = dict(witness._reservation_ledger_policy(self.cfg))
        policy.update(
            {
                "max_active_rows": 10_000,
                "max_active_bytes": 256 * 1024 * 1024,
            }
        )
        row = {"receipt": receipt(), "status": "reserved"}

        # Exercise the exact row boundary without paying for three 147 MB JSON
        # serializations; the full-body serialization is exercised immediately
        # below at the decisive 10,000-row boundary.
        with mock.patch.object(witness.json, "dumps", return_value="{}"):
            for count in (9_999, 10_000):
                ledger = witness._empty_ledger()
                ledger["reservations"] = [row] * count
                self.assertEqual(witness._snapshot_text(ledger, policy), "{}\n")
            ledger["reservations"].append(row)
            with self.assertRaises(SystemExit):
                witness._snapshot_text(ledger, policy)

        # The adversarial fixture carries a complete 7,000-byte ML-DSA
        # signature. Ten thousand real receipt bodies must fit with substantial
        # byte headroom, not merely pass a row-count check.
        ledger = witness._empty_ledger()
        ledger["reservations"] = [row] * 10_000
        encoded = witness._snapshot_text(ledger, policy).encode("utf-8")
        self.assertGreater(len(encoded), 140 * 1024 * 1024)
        self.assertLess(len(encoded), policy["max_active_bytes"])

    def test_archive_or_space_failure_never_discards_active_receipt(self):
        for label, archive_side_effect, free_bytes in (
            ("archive", SystemExit(2), None),
            ("space", None, 0),
        ):
            with self.subTest(label=label):
                ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
                archive = mock.patch.object(
                    witness, "_archive_terminal", side_effect=archive_side_effect
                )
                free = (
                    mock.patch.object(witness, "_state_free_bytes", return_value=free_bytes)
                    if free_bytes is not None
                    else mock.patch.object(
                        witness, "_state_free_bytes", wraps=witness._state_free_bytes
                    )
                )
                with archive, free, self.assertRaises(SystemExit):
                    witness._reconcile(
                        ledger, self.beat(199), FakeRpc(self.txid), self.cfg, self.paths
                    )
                restored = witness._load_ledger(self.paths["ledger"], self.cfg)
                self.assertEqual(len(restored["reservations"]), 1)
                self.assertEqual(restored["terminal_count"], 0)

    def test_append_before_checkpoint_crash_is_exactly_recoverable(self):
        ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
        entry = ledger["reservations"][0]
        entry.update({"status": "final", "block_height": 99, "block_hash": BLOCK_HASH})
        beat = self.beat(199)
        archive_entry = witness._terminal_archive_entry(entry, beat)
        archive_sha = hashlib.sha256(witness._canonical_json_bytes(archive_entry)).hexdigest()
        record = witness._make_tombstone(entry, beat, 1, witness.ZERO_HASH, archive_sha)
        # Model power loss after fsynced append and before active checkpoint.
        witness._append_tombstone(
            self.paths, ledger, record, witness._reservation_ledger_policy(self.cfg)
        )

        recovered = witness._load_ledger(self.paths["ledger"], self.cfg)
        self.assertTrue(recovered["_needs_checkpoint"])
        self.assertEqual(recovered["reservations"], [])
        self.assertEqual(recovered["terminal_count"], 1)
        witness._persist_ledger(self.paths, recovered, witness._reservation_ledger_policy(self.cfg))
        stable = witness._load_ledger(self.paths["ledger"], self.cfg)
        self.assertFalse(stable["_needs_checkpoint"])

    def test_tamper_truncation_and_unbound_tail_fail_closed(self):
        ledger = witness._load_ledger(self.paths["ledger"], self.cfg)
        entry = ledger["reservations"][0]
        entry.update({"status": "final", "block_height": 99, "block_hash": BLOCK_HASH})
        beat = self.beat(199)
        archive_entry = witness._terminal_archive_entry(entry, beat)
        record = witness._make_tombstone(
            entry,
            beat,
            1,
            witness.ZERO_HASH,
            hashlib.sha256(witness._canonical_json_bytes(archive_entry)).hexdigest(),
        )
        witness._append_tombstone(
            self.paths, ledger, record, witness._reservation_ledger_policy(self.cfg)
        )
        path = Path(self.paths["terminal"])
        original = path.read_bytes()

        path.write_bytes(original[:-1])
        path.chmod(0o600)
        with self.assertRaises(SystemExit):
            witness._load_ledger(self.paths["ledger"], self.cfg)
        path.write_bytes(original.replace(b'"sats":1', b'"sats":2', 1))
        path.chmod(0o600)
        with self.assertRaises(SystemExit):
            witness._load_ledger(self.paths["ledger"], self.cfg)

    def test_production_archive_hook_requires_absolute_safe_executable(self):
        def configured(command):
            cfg = dict(self.cfg)
            cfg["reservation_ledger"] = dict(self.cfg["reservation_ledger"])
            cfg["reservation_ledger"].update(
                {
                    "max_active_rows": 10_000,
                    "max_active_bytes": 256 * 1024 * 1024,
                    "terminal_archive_command": command,
                }
            )
            return cfg

        undersized = configured(["/archive-hook"])
        undersized["reservation_ledger"]["max_active_rows"] = 9_999
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(undersized, production=True)
        undersized = configured(["/archive-hook"])
        undersized["reservation_ledger"]["max_active_bytes"] = 256 * 1024 * 1024 - 1
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(undersized, production=True)

        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(configured(["relative-hook"]), production=True)
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(
                configured([str(self.state / "missing-hook")]), production=True
            )

        hook = self.state / "archive-hook"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hook.chmod(0o700)
        accepted = witness._reservation_ledger_policy(configured([str(hook)]), production=True)
        self.assertEqual(accepted["terminal_archive_command"], [str(hook)])

        hook.chmod(0o722)
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(configured([str(hook)]), production=True)
        hook.chmod(0o700)
        link = self.state / "archive-hook-link"
        link.symlink_to(hook)
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(configured([str(link)]), production=True)

    def test_archive_hook_ack_is_exact_and_digest_bound(self):
        entry = {
            "version": 1,
            "kind": witness.TERMINAL_ARCHIVE_KIND,
            "receipt": self.receipt,
            "txid": self.txid,
            "signed_tx_sha256": self.signed_digest,
            "block_height": 99,
            "block_hash": BLOCK_HASH,
            "finalized_at_tip": 199,
            "finalized_at_tip_hash": TIP_HASH,
        }
        digest = hashlib.sha256(witness._canonical_json_bytes(entry)).hexdigest()
        policy = witness._reservation_ledger_policy(self.cfg)
        now = 1_700_000_000
        retention = now + witness.TERMINAL_ARCHIVE_RETENTION_SECONDS
        good_answer = {
            "version": 1,
            "stored": True,
            "durable": True,
            "entry_sha256": digest,
            "readback_sha256": digest,
            "archive_id": "worm/object/version-1",
            "object_lock_mode": "COMPLIANCE",
            "retention_until": retention,
        }
        good = mock.Mock(returncode=0, stderr="", stdout=json.dumps(good_answer))
        with (
            mock.patch.object(witness, "run_bounded_subprocess", return_value=good) as run,
            mock.patch.object(witness.time, "time", return_value=now),
        ):
            self.assertEqual(witness._archive_terminal(entry, digest, policy), good_answer)
        sent = json.loads(run.call_args.kwargs["input_text"])
        self.assertEqual(sent["entry"], entry)
        self.assertEqual(sent["entry_sha256"], digest)
        self.assertEqual(sent["minimum_retention_until"], retention)

        mutations = {
            "readback": {**good_answer, "readback_sha256": "00" * 32},
            "governance": {**good_answer, "object_lock_mode": "GOVERNANCE"},
            "short-retention": {**good_answer, "retention_until": retention - 1},
            "not-durable": {**good_answer, "durable": False},
            "extra-field": {**good_answer, "extra": True},
        }
        for label, answer in mutations.items():
            with (
                self.subTest(label),
                mock.patch.object(
                    witness,
                    "run_bounded_subprocess",
                    return_value=mock.Mock(returncode=0, stderr="", stdout=json.dumps(answer)),
                ),
                mock.patch.object(witness.time, "time", return_value=now),
                self.assertRaises(SystemExit),
            ):
                witness._archive_terminal(entry, digest, policy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
