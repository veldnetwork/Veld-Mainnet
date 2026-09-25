#!/usr/bin/env python3
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import reconcile_mint_state as reconcile
import veld_signerd as signer


class MintStateReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mint-reconcile-")
        self.root = Path(self.temp.name)
        self.state = self.root / "signer-state.json"
        self.old = {
            "signed": [
                {"sats": 30, "to": "Vone", "at": 1},
                {"sats": 20, "to": "Vtwo", "at": 2},
            ],
            "total_signed": 100,
        }
        self.old_bytes = (json.dumps(self.old, separators=(",", ":")) + "\n").encode()
        self.state.write_bytes(self.old_bytes)
        self.state.chmod(0o600)
        (self.root / "HALT").write_text("operator halt\n")
        entries = signer._legacy_pending_entries(self.old)
        self.artifact = {
            "version": 1,
            "kind": reconcile.ARTIFACT_KIND,
            "old_state_sha256": hashlib.sha256(self.old_bytes).hexdigest(),
            "canonical_tip": {"height": 250, "hash": "11" * 32},
            "supply_sats": 100,
            "custody_sats": 200,
            "margin_sats": 10,
            "wait_evidence": {
                "signer_halted": True,
                "minter_halted": True,
                "mint_mempool_empty": True,
                "minter_queue_empty": True,
                "witness_restore_halt_armed": True,
                "quiesced_height": 100,
                "observed_height": 250,
                "observed_tip_hash": "11" * 32,
            },
            "resolved_requests": [
                {
                    "request_id": entry["request_id"],
                    "sats": entry["sats"],
                    "disposition": "canonical_final",
                    "txid": ("%02x" % (index + 1)) * 32,
                    "block_height": 100 + index,
                    "block_hash": "22" * 32,
                }
                for index, entry in enumerate(entries)
            ],
            "omitted_journal_floor": {
                "sats": 0,
                "disposition": "resolved_inventory",
                "evidence_sha256": "33" * 32,
            },
        }
        statement_sha = hashlib.sha256(reconcile.canonical_statement(self.artifact)).hexdigest()
        self.artifact["approvals"] = [
            {"operator_id": "op-a", "statement_sha256": statement_sha, "signature_hex": "00"},
            {"operator_id": "op-b", "statement_sha256": statement_sha, "signature_hex": "01"},
        ]
        self.keygen = self.root / "fake-keygen"
        self.keygen.write_text("#!/bin/sh\nexit 0\n")
        self.keygen.chmod(0o700)
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

    def tearDown(self):
        self.temp.cleanup()

    def validate(self, artifact=None):
        artifact = artifact or self.artifact
        inventory = reconcile.validate_evidence(
            artifact, hashlib.sha256(self.old_bytes).hexdigest(), self.old
        )
        operators, ignored = reconcile.verify_approvals(artifact, self.policy, str(self.keygen))
        return reconcile.transform(self.old, artifact, "44" * 32, operators, inventory)

    def test_two_approved_transform_retains_tombstones_and_atomic_backup(self):
        result = self.validate()
        self.assertEqual(result["signed"], [])
        self.assertEqual(result["mint_accounting"]["pending"], [])
        self.assertEqual(len(result["legacy_reconciliation"]["resolved_tombstones"]), 2)
        backup = reconcile.atomic_apply(str(self.state), self.old_bytes, result)
        self.assertEqual(Path(backup).read_bytes(), self.old_bytes)
        applied = json.loads(self.state.read_text())
        self.assertEqual(applied["legacy_reconciliation"]["operator_ids"], ["op-a", "op-b"])

    def test_hash_wait_approval_and_unresolved_fail_closed(self):
        bad = copy.deepcopy(self.artifact)
        bad["old_state_sha256"] = "00" * 32
        with self.assertRaisesRegex(RuntimeError, "exact old"):
            reconcile.validate_evidence(bad, hashlib.sha256(self.old_bytes).hexdigest(), self.old)
        bad = copy.deepcopy(self.artifact)
        bad["wait_evidence"]["observed_height"] = 200
        bad["canonical_tip"]["height"] = 200
        with self.assertRaisesRegex(RuntimeError, "strictly beyond"):
            reconcile.validate_evidence(bad, hashlib.sha256(self.old_bytes).hexdigest(), self.old)
        bad = copy.deepcopy(self.artifact)
        bad["approvals"] = bad["approvals"][:1]
        with self.assertRaisesRegex(RuntimeError, "two operator"):
            reconcile.verify_approvals(bad, self.policy, str(self.keygen))
        bad = copy.deepcopy(self.artifact)
        bad["resolved_requests"][0]["disposition"] = "unresolved"
        with self.assertRaisesRegex(RuntimeError, "final or provably invalidated"):
            inventory = reconcile.validate_evidence(
                bad, hashlib.sha256(self.old_bytes).hexdigest(), self.old
            )
            reconcile.transform(self.old, bad, "44" * 32, ["op-a", "op-b"], inventory)

    def test_signer_never_silently_migrates_legacy_state(self):
        before = copy.deepcopy(self.old)
        with self.assertRaisesRegex(ValueError, "offline"):
            signer._initialize_mint_accounting(self.old)
        self.assertEqual(self.old, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
