#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import reconcile_mint_state as legacy
import reconcile_witness_restore as restore
import veld_peg_solvency as sol
import veld_signerd as signer
import veld_wt_reserve as witness


ISSUER = "Vissuer"
WITNESS = "witness-1"
ADDR1 = "V" + "1" * 25
ADDR2 = "V" + "2" * 25
ADDR3 = "V" + "3" * 25
ADDR4 = "V" + "4" * 25


def unsigned_tx(tag):
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


def receipt(tag, sats, recipient):
    unsigned = unsigned_tx(tag)
    request_id = hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
    return {
        "v": sol.RESERVATION_VERSION,
        "kind": sol.RESERVATION_KIND,
        "issuer_id": ISSUER,
        "witness_id": WITNESS,
        "request_id": request_id,
        "unsigned_tx_sha256": request_id,
        "reservation_id": sol.reservation_id(
            ISSUER, request_id, request_id, sats, recipient, None, None
        ),
        "sats": sats,
        "recipient": recipient,
        "beat_seq": tag,
        "tip": 100,
        "tip_hash": "11" * 32,
        "headroom_sats": 1000,
        "allocation_verified": False,
        "allocation_request_id": None,
        "allocation_descriptor_index": None,
        "allocation_btc_address": None,
        "allocation_script_pubkey": None,
        "deposit_outpoint": None,
        "reserved_at": tag,
        "sig_alg": "mldsa65",
        "sig": "00",
    }


def c1_receipt(descriptor_index, range_end=10999):
    unsigned = unsigned_tx(9)
    request_id = hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
    allocation_request_id = "0" * 31 + "1"
    outpoint = "22" * 32 + ":0"
    return {
        "v": sol.C1_RESERVATION_VERSION,
        "kind": sol.RESERVATION_KIND,
        "issuer_id": ISSUER,
        "witness_id": WITNESS,
        "request_id": request_id,
        "unsigned_tx_sha256": request_id,
        "reservation_id": sol.reservation_id(
            ISSUER, request_id, request_id, 100_000, ADDR1, outpoint, allocation_request_id
        ),
        "sats": 100_000,
        "recipient": ADDR1,
        "beat_seq": 9,
        "tip": 250,
        "tip_hash": "11" * 32,
        "headroom_sats": 1_000_000,
        "allocation_verified": True,
        "allocation_request_id": allocation_request_id,
        "allocation_descriptor_index": descriptor_index,
        "allocation_btc_address": "bc1p" + "q" * 58,
        "allocation_script_pubkey": "5120" + "ab" * 32,
        "deposit_outpoint": outpoint,
        "allocation_capacity_policy_sha256": "aa" * 32,
        "allocation_public_descriptor_range_start": 1000,
        "allocation_public_descriptor_range_end": range_end,
        "reserved_at": 9,
        "sig_alg": "mldsa65",
        "sig": "00",
    }


class WitnessRestoreReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="witness-restore-")
        self.root = Path(self.temp.name)
        self.state_dir = self.root / "state"
        self.state_dir.mkdir(mode=0o700)
        self.paths = witness._paths({"state_dir": str(self.state_dir)})
        Path(self.paths["restore_halt"]).write_text("restore halt\n")
        Path(self.paths["restore_halt"]).chmod(0o600)
        self.keygen = self.root / "veld-keygen"
        self.keygen.write_text("#!/bin/sh\nexit 0\n")
        self.keygen.chmod(0o700)
        self.pubkey = self.root / "beat.pub"
        self.pubkey.write_text("fixture")
        self.pub_a = self.root / "a.pub"
        self.pub_a.write_text("a")
        self.pub_b = self.root / "b.pub"
        self.pub_b.write_text("b")
        self.policy = {
            "operators": [
                {"operator_id": "op-a", "pubkey_file": str(self.pub_a)},
                {"operator_id": "op-b", "pubkey_file": str(self.pub_b)},
            ]
        }
        self.policy_bytes = (
            json.dumps(self.policy, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

        self.r1 = receipt(1, 10, ADDR1)
        self.r2 = receipt(2, 20, ADDR2)
        self.ledger = witness._empty_ledger()
        self.ledger["reservations"] = [
            {"receipt": self.r1, "status": "reserved"},
        ]
        self.ledger_bytes = restore._ledger_payload(self.ledger)
        ledger_path = Path(self.paths["ledger"])
        ledger_path.write_bytes(self.ledger_bytes)
        ledger_path.chmod(0o600)
        self.terminal_bytes = witness._empty_terminal_log_text().encode("utf-8")
        terminal_path = Path(self.paths["terminal"])
        terminal_path.write_bytes(self.terminal_bytes)
        terminal_path.chmod(0o600)

        signed = signed_tx(unsigned_tx(2))
        signed_bytes = bytes.fromhex(signed)
        txid = hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest()
        self.r2_txid = txid
        self.signer_state = {
            "signed": [
                {
                    "request_id": self.r2["request_id"],
                    "txid": txid,
                    "signed_tx_hex": signed,
                    "sats": 20,
                    "to": ADDR2,
                    "at": 1,
                    "witness_receipt": self.r2,
                    "witness_committed": True,
                }
            ],
            "mint_accounting": {
                "version": signer.MINT_ACCOUNTING_VERSION,
                "pending": [
                    {
                        "request_id": self.r2["request_id"],
                        "txid": txid,
                        "sats": 20,
                        "signed_at": 1,
                        "witness_receipt": self.r2,
                        "witness_committed": True,
                    }
                ],
                "confirmed": [],
            },
        }
        self.signer_path = self.root / "signer-state.json"
        self.signer_bytes = (
            json.dumps(self.signer_state, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        self.signer_path.write_bytes(self.signer_bytes)
        self.signer_path.chmod(0o600)
        self.artifact = {
            "version": restore.ARTIFACT_VERSION,
            "kind": restore.ARTIFACT_KIND,
            "restored_ledger_sha256": hashlib.sha256(self.ledger_bytes).hexdigest(),
            "restored_terminal_log_sha256": hashlib.sha256(self.terminal_bytes).hexdigest(),
            "approval_policy_sha256": hashlib.sha256(self.policy_bytes).hexdigest(),
            "beat_pubkey_sha256": hashlib.sha256(self.pubkey.read_bytes()).hexdigest(),
            "signer_state_sha256s": [hashlib.sha256(self.signer_bytes).hexdigest()],
            "ledger_snapshot_sha256s": [],
            "receipt_archive_sha256s": [],
            "source_inventory_complete": True,
            "issuer_id": ISSUER,
            "witness_id": WITNESS,
            "canonical_tip": {"height": 250, "hash": "22" * 32},
            "supply_sats": 30,
            "custody_sats": 100,
            "margin_sats": 10,
            "wait_evidence": {
                "signer_halted": True,
                "minter_halted": True,
                "witness_halted": True,
                "mint_mempool_empty": True,
                "minter_queue_empty": True,
                "quiesced_height": 100,
                "observed_height": 250,
                "observed_tip_hash": "22" * 32,
            },
            "reservations": [
                {"reservation_id": self.r1["reservation_id"], "disposition": "outstanding"},
                {
                    "reservation_id": self.r2["reservation_id"],
                    "disposition": "canonical_final",
                    "txid": txid,
                    "block_height": 100,
                    "block_hash": "33" * 32,
                },
            ],
        }
        statement_sha = hashlib.sha256(legacy.canonical_statement(self.artifact)).hexdigest()
        self.artifact["approvals"] = [
            {"operator_id": "op-a", "statement_sha256": statement_sha, "signature_hex": "00"},
            {"operator_id": "op-b", "statement_sha256": statement_sha, "signature_hex": "01"},
        ]

    def tearDown(self):
        self.temp.cleanup()

    def inventory(self, state=None, ledger=None):
        return restore.collect_inventory(
            restore.validate_restored_ledger(ledger or self.ledger),
            [("mint-primary", state or self.signer_state)],
            str(self.keygen),
            str(self.pubkey),
        )

    def test_c1_receipt_policy_boundaries_restart_and_tombstone_reload(self):
        for descriptor_index, accepted in (
            (1000, True),
            (10999, True),
            (999, False),
            (11000, False),
        ):
            with self.subTest(descriptor_index=descriptor_index):
                ok, _why = sol.validate_reservation_receipt(c1_receipt(descriptor_index))
                self.assertEqual(ok, accepted)

        active_receipt = c1_receipt(10999)
        signer_allocation = {
            "request_id": "cd" * 16,
            "consensus_allocation_id": active_receipt["allocation_request_id"],
            "descriptor_index": active_receipt["allocation_descriptor_index"],
            "btc_address": active_receipt["allocation_btc_address"],
            "script_pubkey": active_receipt["allocation_script_pubkey"],
            "deposit_outpoint": active_receipt["deposit_outpoint"],
            "capacity_policy_sha256": active_receipt["allocation_capacity_policy_sha256"],
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
        }
        heartbeat = {
            "seq": active_receipt["beat_seq"],
            "tip": active_receipt["tip"],
            "tip_hash": active_receipt["tip_hash"],
            "headroom_sats": active_receipt["headroom_sats"],
        }
        with (
            mock.patch.object(signer, "_secure_text", return_value="00"),
            mock.patch.object(
                signer, "run_bounded_subprocess", return_value=mock.Mock(returncode=0)
            ),
        ):
            signer.verify_reservation_receipt(
                active_receipt,
                ISSUER,
                {"witness_id": WITNESS},
                active_receipt["request_id"],
                active_receipt["unsigned_tx_sha256"],
                active_receipt["sats"],
                active_receipt["recipient"],
                heartbeat,
                signer_allocation,
            )
            for field, value in (
                ("allocation_descriptor_index", 999),
                ("allocation_capacity_policy_sha256", "bb" * 32),
                ("allocation_public_descriptor_range_end", 11000),
            ):
                with self.subTest(signer_tamper=field):
                    tampered = copy.deepcopy(active_receipt)
                    tampered[field] = value
                    with self.assertRaises(ValueError):
                        signer.verify_reservation_receipt(
                            tampered,
                            ISSUER,
                            {"witness_id": WITNESS},
                            tampered["request_id"],
                            tampered["unsigned_tx_sha256"],
                            tampered["sats"],
                            tampered["recipient"],
                            heartbeat,
                            signer_allocation,
                        )

        ledger = witness._empty_ledger()
        ledger["reservations"] = [{"receipt": active_receipt, "status": "reserved"}]
        witness.atomic_write(
            self.paths["ledger"], json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n"
        )
        restarted = witness._load_ledger(self.paths["ledger"])
        self.assertEqual(
            restarted["reservations"][0]["receipt"]["allocation_descriptor_index"], 10999
        )

        entry = {
            "receipt": active_receipt,
            "status": "final",
            "txid": "33" * 32,
            "signed_tx_sha256": "44" * 32,
            "block_height": 100,
            "block_hash": "55" * 32,
        }
        beat = {"tip": 250, "tip_hash": "66" * 32}
        tombstone = witness._make_tombstone(entry, beat, 1, witness.ZERO_HASH, "77" * 32)
        self.assertEqual(tombstone["version"], witness.C1_TOMBSTONE_VERSION)
        tampered_tombstone = copy.deepcopy(tombstone)
        tampered_tombstone["allocation_capacity_policy_sha256"] = "bb" * 32
        tampered_tombstone["record_sha256"] = hashlib.sha256(
            witness._tombstone_payload(tampered_tombstone)
        ).hexdigest()
        self.assertFalse(witness._same_tombstone_identity(active_receipt, tampered_tombstone))
        terminal_text = (
            witness._empty_terminal_log_text()
            + json.dumps(tombstone, sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        witness.atomic_write(self.paths["terminal"], terminal_text)
        compacted = witness._empty_ledger()
        compacted["terminal_count"] = 1
        compacted["terminal_head_sha256"] = tombstone["record_sha256"]
        witness.atomic_write(
            self.paths["ledger"],
            json.dumps(compacted, sort_keys=True, separators=(",", ":")) + "\n",
        )
        terminal_restarted = witness._load_ledger(self.paths["ledger"])
        self.assertEqual(terminal_restarted["_terminals"][0]["allocation_descriptor_index"], 10999)

    def test_union_two_approved_finality_and_atomic_apply(self):
        inventory = self.inventory()
        self.assertEqual(set(inventory), {self.r1["reservation_id"], self.r2["reservation_id"]})
        result = restore.validate_artifact(
            self.artifact,
            hashlib.sha256(self.ledger_bytes).hexdigest(),
            hashlib.sha256(self.terminal_bytes).hexdigest(),
            [hashlib.sha256(self.signer_bytes).hexdigest()],
            inventory,
            [],
            approval_policy_sha=hashlib.sha256(self.policy_bytes).hexdigest(),
            beat_pubkey_sha=hashlib.sha256(self.pubkey.read_bytes()).hexdigest(),
        )
        operators, ignored = legacy.verify_approvals(self.artifact, self.policy, str(self.keygen))
        self.assertEqual(operators, ["op-a", "op-b"])
        by_id = {x["receipt"]["reservation_id"]: x for x in result["reservations"]}
        self.assertEqual(by_id[self.r1["reservation_id"]]["status"], "reserved")
        self.assertEqual(by_id[self.r2["reservation_id"]]["status"], "final")
        artifact_sha = "44" * 32
        backup, terminal_backup, audit = restore.atomic_apply(
            self.paths, self.ledger_bytes, self.terminal_bytes, result, artifact_sha
        )
        self.assertEqual(Path(backup).read_bytes(), self.ledger_bytes)
        self.assertEqual(Path(terminal_backup).read_bytes(), self.terminal_bytes)
        self.assertFalse(Path(self.paths["restore_halt"]).exists())
        self.assertTrue(Path(audit).is_file())
        applied = json.loads(Path(self.paths["ledger"]).read_text())
        self.assertEqual(len(applied["reservations"]), 2)

    def test_exact_depth_missing_union_and_insolvency_refuse(self):
        inventory = self.inventory()
        bad = copy.deepcopy(self.artifact)
        bad["canonical_tip"]["height"] = 200
        bad["wait_evidence"]["observed_height"] = 200
        bad["reservations"][1]["block_height"] = 100
        with self.assertRaisesRegex(RuntimeError, "strictly beyond"):
            restore.validate_artifact(
                bad,
                hashlib.sha256(self.ledger_bytes).hexdigest(),
                hashlib.sha256(self.terminal_bytes).hexdigest(),
                [hashlib.sha256(self.signer_bytes).hexdigest()],
                inventory,
                [],
            )
        bad = copy.deepcopy(self.artifact)
        bad["reservations"] = bad["reservations"][:1]
        with self.assertRaisesRegex(RuntimeError, "exact receipt union"):
            restore.validate_artifact(
                bad,
                hashlib.sha256(self.ledger_bytes).hexdigest(),
                hashlib.sha256(self.terminal_bytes).hexdigest(),
                [hashlib.sha256(self.signer_bytes).hexdigest()],
                inventory,
                [],
            )
        bad = copy.deepcopy(self.artifact)
        bad["custody_sats"] = 39
        with self.assertRaisesRegex(RuntimeError, "insolvent"):
            restore.validate_artifact(
                bad,
                hashlib.sha256(self.ledger_bytes).hexdigest(),
                hashlib.sha256(self.terminal_bytes).hexdigest(),
                [hashlib.sha256(self.signer_bytes).hexdigest()],
                inventory,
                [],
            )

    def test_signed_bytes_conflicts_and_malformed_ledger_refuse(self):
        bad_state = copy.deepcopy(self.signer_state)
        bad_state["signed"][0]["signed_tx_hex"] = signed_tx(unsigned_tx(9))
        with self.assertRaisesRegex(RuntimeError, "does not bind"):
            self.inventory(state=bad_state)
        bad_ledger = copy.deepcopy(self.ledger)
        bad_ledger["reservations"][0]["unexpected"] = True
        with self.assertRaisesRegex(RuntimeError, "invalid fields"):
            self.inventory(ledger=bad_ledger)
        bad_receipt = copy.deepcopy(self.signer_state)
        bad_receipt["signed"][0]["witness_receipt"]["sig"] = "GG"
        bad_receipt["mint_accounting"]["pending"][0]["witness_receipt"]["sig"] = "GG"
        with self.assertRaisesRegex(RuntimeError, "reservation signature is malformed"):
            self.inventory(state=bad_receipt)

        legacy_v2 = {"version": 2, "reservations": copy.deepcopy(self.ledger["reservations"])}
        migrated = restore.validate_restored_ledger(legacy_v2)
        self.assertEqual(migrated["version"], witness.LEDGER_VERSION)
        self.assertEqual(migrated["terminal_count"], 0)
        self.assertEqual(migrated["terminal_head_sha256"], witness.ZERO_HASH)

    def test_immutable_snapshot_and_receipt_archive_extend_union(self):
        r3 = receipt(3, 30, ADDR3)
        r4 = receipt(4, 40, ADDR4)
        snapshot = witness._empty_ledger()
        snapshot["reservations"] = [{"receipt": r3, "status": "reserved"}]
        archive = {"version": 1, "kind": "VELD_MINT_RECEIPT_ARCHIVE", "entries": [{"receipt": r4}]}
        inventory = restore.collect_inventory(
            self.ledger,
            [("mint-primary", self.signer_state)],
            str(self.keygen),
            str(self.pubkey),
            ledger_snapshots=[("worm-ledger", snapshot)],
            receipt_archives=[("worm-receipts", archive)],
        )
        self.assertEqual(
            set(inventory),
            {
                self.r1["reservation_id"],
                self.r2["reservation_id"],
                r3["reservation_id"],
                r4["reservation_id"],
            },
        )
        bad_archive = copy.deepcopy(archive)
        bad_archive["entries"][0]["txid"] = "00" * 32
        with self.assertRaisesRegex(RuntimeError, "invalid fields"):
            restore.collect_inventory(
                self.ledger,
                [("mint-primary", self.signer_state)],
                str(self.keygen),
                str(self.pubkey),
                receipt_archives=[("bad", bad_archive)],
            )

    def test_terminal_tombstone_requires_exact_worm_object_and_stays_compact(self):
        signed = signed_tx(unsigned_tx(1))
        signed_bytes = bytes.fromhex(signed)
        txid = hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest()
        entry = {
            "receipt": self.r1,
            "status": "final",
            "txid": txid,
            "signed_tx_sha256": hashlib.sha256(signed_bytes).hexdigest(),
            "block_height": 100,
            "block_hash": "33" * 32,
        }
        beat = {"tip": 250, "tip_hash": "22" * 32}
        terminal_archive = witness._terminal_archive_entry(entry, beat)
        archive_sha = hashlib.sha256(witness._canonical_json_bytes(terminal_archive)).hexdigest()
        tombstone = witness._make_tombstone(entry, beat, 1, witness.ZERO_HASH, archive_sha)
        terminal_bytes = (
            witness._empty_terminal_log_text()
            + json.dumps(tombstone, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
        terminals = restore.validate_terminal_log_bytes(terminal_bytes)
        ledger = witness._empty_ledger()
        ledger["terminal_count"] = 1
        ledger["terminal_head_sha256"] = tombstone["record_sha256"]

        with self.assertRaisesRegex(RuntimeError, "full receipt"):
            restore.collect_inventory(
                ledger, [], str(self.keygen), str(self.pubkey), terminal_tombstones=terminals
            )
        inventory = restore.collect_inventory(
            ledger,
            [],
            str(self.keygen),
            str(self.pubkey),
            receipt_archives=[("worm-terminal", terminal_archive)],
            terminal_tombstones=terminals,
        )
        self.assertEqual(inventory[self.r1["reservation_id"]]["tombstone"], tombstone)

        artifact = copy.deepcopy(self.artifact)
        ledger_bytes = restore._ledger_payload(ledger)
        artifact.update(
            {
                "restored_ledger_sha256": hashlib.sha256(ledger_bytes).hexdigest(),
                "restored_terminal_log_sha256": hashlib.sha256(terminal_bytes).hexdigest(),
                "signer_state_sha256s": [],
                "reservations": [
                    {
                        "reservation_id": self.r1["reservation_id"],
                        "disposition": "canonical_final",
                        "txid": txid,
                        "block_height": 100,
                        "block_hash": "33" * 32,
                    }
                ],
            }
        )
        result = restore.validate_artifact(
            artifact,
            hashlib.sha256(ledger_bytes).hexdigest(),
            hashlib.sha256(terminal_bytes).hexdigest(),
            [],
            inventory,
            terminals,
        )
        self.assertEqual(result["reservations"], [])
        self.assertEqual(result["terminal_count"], 1)

        mutated_archive = copy.deepcopy(terminal_archive)
        mutated_archive["finalized_at_tip_hash"] = "44" * 32
        with self.assertRaisesRegex(RuntimeError, "digest-bound WORM"):
            restore.collect_inventory(
                ledger,
                [],
                str(self.keygen),
                str(self.pubkey),
                receipt_archives=[("mutated", mutated_archive)],
                terminal_tombstones=terminals,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
