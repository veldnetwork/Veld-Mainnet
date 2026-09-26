#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from swap import veld_c1_reservationd as coordinator
from swap import veld_wrapd as wrapd


REQUEST_ID = "12" * 16
VELD = "V" + "2" * 33
SCRIPT = "5120" + "11" * 32


def allocation(now=1):
    return {
        "request_id": REQUEST_ID,
        "principal_hash": "22" * 32,
        "veld_address": VELD,
        "amount_sats": 10_000,
        "descriptor_index": 1000,
        "btc_address": "bc1p" + "q" * 58,
        "script_pubkey": SCRIPT,
        "admitted_at": now,
        "commitment_blind": "44" * 32,
        "consensus_allocation_id": "0" * 31 + "1",
        "expires_at": now + 7 * 24 * 60 * 60,
        "capacity_policy_sha256": "33" * 32,
    }


class WrapLifecycleTests(unittest.TestCase):
    def journal(self, callback):
        journal = object.__new__(wrapd.WrapAllocationJournal)
        journal.legacy_fixture = False
        journal.ensure_consensus_reservation = callback
        journal.events = []
        return journal

    def response(self, record):
        return {
            "expires_at": record["expires_at"],
            "deposit_observed_at": None,
            "funded_reserved_at": None,
            "minted_at": None,
        }

    def test_confirmation_wait_consumes_none_of_seven_day_send_window(self):
        record = allocation(1)
        record["state"] = "issued"
        status = {
            "created_height": 1,
            "exposed_height": 102,
            "confirmations": 101,
            "tip": 202,
            "funded": False,
            "send_starts_height": 202,
            "recommended_send_cutoff_height": 3_360,
            "funding_accepts_through_height": 3_461,
            "funding_expires_height": 3_561,
        }
        journal = self.journal(lambda _record: dict(status))
        # The old pre-reveal wall deadline has elapsed, but exposure is
        # canonical and the complete 3,360-height user window begins now.
        result = journal._lifecycle_result(record, self.response(record), record["expires_at"] + 1)
        self.assertEqual(result["send_starts_height"], 202)
        self.assertEqual(result["recommended_send_cutoff_height"], 3_360)
        self.assertEqual(result["funding_accepts_through_height"], 3_461)
        self.assertEqual(result["funding_expires_height"], 3_561)
        self.assertTrue(result["send_allowed"])
        self.assertTrue(result["consensus_capacity_reserved"])

        for tip, allowed in (
            (3_359, True),
            (3_360, True),
            (3_361, False),
            (3_461, False),
            (3_561, False),
        ):
            with self.subTest(tip=tip):
                boundary = dict(status, tip=tip)
                outcome = self.journal(lambda _record, value=boundary: value)._lifecycle_result(
                    record, self.response(record), record["expires_at"] + 2
                )
                self.assertIs(outcome["send_allowed"], allowed)
                self.assertEqual(outcome["lifecycle"], "UNFUNDED" if allowed else "RECOVERY_ONLY")
                self.assertTrue(outcome["consensus_capacity_reserved"])

    def test_pre_exposure_intent_can_expire_but_exposed_pending_cannot(self):
        record = allocation(1)
        record["state"] = "issued"
        pending_unexposed = wrapd.PendingConsensusReservation(
            {
                "found": False,
                "active": False,
                "retired": True,
                "exposed": False,
                "confirmations": 50,
                "required_confirmations": 101,
            }
        )
        cancelled = self.journal(lambda _record: (_ for _ in ()).throw(pending_unexposed))
        cancelled.events = [{"action": "expired", "request_id": record["request_id"]}]
        with self.assertRaises(wrapd.ExpiredAllocation):
            cancelled._lifecycle_result(record, self.response(record), record["expires_at"])

        pending_exposed = wrapd.PendingConsensusReservation(
            {
                "found": True,
                "active": True,
                "exposed": True,
                "confirmations": 50,
                "required_confirmations": 101,
            }
        )
        with self.assertRaises(wrapd.PendingConsensusReservation):
            self.journal(lambda _record: (_ for _ in ()).throw(pending_exposed))._lifecycle_result(
                record, self.response(record), record["expires_at"]
            )

    def test_pending_public_status_never_contains_address_or_script(self):
        record = allocation(1)
        completed = subprocess.CompletedProcess(
            [],
            75,
            stdout=json.dumps(
                {
                    "version": 3,
                    "allocation_id": record["consensus_allocation_id"],
                    "found": False,
                    "active": False,
                    "retired": False,
                    "last_sequence": 0,
                    "exposed": False,
                    "funded": False,
                    "funding_outpoint": None,
                    "confirmations": 0,
                    "required_confirmations": 101,
                    "canonical_depth_reached": False,
                }
            ),
            stderr="",
        )
        node_status = {
            "allocation_id": record["consensus_allocation_id"],
            "found": False,
            "active": False,
            "retired": False,
            "exposed": False,
            "tip": 1,
            "confirmations": 0,
            "funded": False,
            "funding_outpoint": None,
            "required_confirmations": 101,
            "canonical_depth_reached": False,
        }
        with (
            mock.patch.object(wrapd, "PRODUCTION", True),
            mock.patch.object(wrapd, "CONSENSUS_RESERVATION_COMMAND", ("/usr/bin/coordinator",)),
            mock.patch.object(wrapd, "run_bounded_subprocess", return_value=completed),
            mock.patch.object(wrapd, "_veld", return_value=node_status),
        ):
            with self.assertRaises(wrapd.PendingConsensusReservation) as caught:
                wrapd._ensure_consensus_reservation(record)
        encoded = json.dumps(caught.exception.status)
        self.assertNotIn(record["btc_address"], encoded)
        self.assertNotIn(record["script_pubkey"], encoded)
        self.assertNotIn("btc_address", caught.exception.status)
        self.assertNotIn("script_pubkey", caught.exception.status)


class CoordinatorDurabilityTests(unittest.TestCase):
    def test_missing_state_requires_one_shot_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")
            cfg = {"state_file": path, "allow_initial_state_creation": False}
            with self.assertRaisesRegex(ValueError, "--initialize"):
                coordinator.load_or_initialize_state(cfg)
            with self.assertRaisesRegex(ValueError, "requires"):
                coordinator.initialize_state(cfg)
            cfg["allow_initial_state_creation"] = True
            with mock.patch.object(coordinator, "persist") as persist:
                with self.assertRaisesRegex(ValueError, "--initialize"):
                    coordinator.load_or_initialize_state(cfg)
                state = coordinator.initialize_state(cfg)
                self.assertEqual(
                    state, {"version": 4, "sequence": 0, "records": {}, "compaction_cursor": None}
                )
                persisted = persist.call_args.args[1]
                self.assertEqual(
                    persisted,
                    {"version": 4, "sequence": 0, "records": {}, "compaction_cursor": None},
                )

    def test_lost_reply_and_restart_replay_only_exact_signed_bytes(self):
        signed = "00"
        stage = {
            "unsigned_tx_hex": "00",
            "unsigned_sha256": hashlib.sha256(b"\x00").hexdigest(),
            "signed_tx_hex": signed,
            "txid": coordinator.txid(signed),
            "broadcast_attempts": 0,
            "last_broadcast_at": None,
            "funding_sha256": None,
            "semantic_sha256": None,
            "funding_outpoint": None,
            "created_at": 1,
            "signer_archive_record_sha256": "11" * 32,
            "signer_archive_id": "worm/signer/1",
            "signer_receipt_sequence": 1,
            "signer_receipt_state_sha256": "22" * 32,
        }
        record = {
            "kind": "active",
            "allocation_sha256": "aa" * 32,
            "request_id": REQUEST_ID,
            "terminal_observed_tip": None,
            "RESERVE": stage,
            "EXPOSE": None,
            "CANCEL": None,
            "FUND": [],
        }
        cfg = {"state_file": "/unused", "reservation_signer_command": ("/usr/bin/signer",)}
        state = {"version": 3, "sequence": 1, "records": {}}
        with (
            mock.patch.object(coordinator, "persist"),
            mock.patch.object(coordinator, "run_bounded_subprocess") as signer,
        ):
            self.assertIs(
                coordinator.prepare_stage(mock.Mock(), cfg, allocation(), "RESERVE", record, state),
                stage,
            )
            signer.assert_not_called()
            rpc = mock.Mock()
            rpc.call.side_effect = [TimeoutError("lost reply"), RuntimeError("already known")]
            self.assertFalse(coordinator.broadcast_exact(rpc, cfg, state, stage))
            self.assertFalse(coordinator.broadcast_exact(rpc, cfg, state, stage))
        self.assertEqual(stage["signed_tx_hex"], signed)
        self.assertEqual(stage["txid"], coordinator.txid(signed))
        self.assertEqual(stage["broadcast_attempts"], 2)
        self.assertEqual([call.args[1] for call in rpc.call.call_args_list], [[signed], [signed]])

    def test_signer_mutation_and_broadcast_txid_mismatch_are_fatal(self):
        unsigned = "00"
        stage = {
            "unsigned_tx_hex": unsigned,
            "unsigned_sha256": hashlib.sha256(b"\x00").hexdigest(),
            "signed_tx_hex": None,
            "txid": None,
            "broadcast_attempts": 0,
            "last_broadcast_at": None,
            "funding_sha256": None,
            "semantic_sha256": None,
            "funding_outpoint": None,
            "created_at": 1,
            "signer_archive_record_sha256": None,
            "signer_archive_id": None,
            "signer_receipt_sequence": None,
            "signer_receipt_state_sha256": None,
        }
        record = {
            "kind": "active",
            "allocation_sha256": "aa" * 32,
            "request_id": REQUEST_ID,
            "terminal_observed_tip": None,
            "RESERVE": stage,
            "EXPOSE": None,
            "CANCEL": None,
            "FUND": [],
        }
        cfg = {"state_file": "/unused", "reservation_signer_command": ("/usr/bin/signer",)}
        state = {"version": 3, "sequence": 1, "records": {}}
        answer = {
            "version": 2,
            "action": "signed_c1_reservation",
            "phase": "RESERVE",
            "request_id": REQUEST_ID,
            "allocation_id": "0" * 31 + "1",
            "signed_tx_hex": "00",
            "txid": coordinator.txid("00"),
        }
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(answer), stderr="")
        with (
            mock.patch.object(coordinator, "persist"),
            mock.patch.object(coordinator, "run_bounded_subprocess", return_value=completed),
            mock.patch.object(
                coordinator.solvency, "unsigned_template_from_signed_hex", return_value="ff"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "does not bind"):
                coordinator.prepare_stage(mock.Mock(), cfg, allocation(), "RESERVE", record, state)

        stage["signed_tx_hex"] = "00"
        stage["txid"] = coordinator.txid("00")
        rpc = mock.Mock()
        rpc.call.return_value = "ff" * 32
        with mock.patch.object(coordinator, "persist"):
            with self.assertRaisesRegex(ValueError, "different transaction"):
                coordinator.broadcast_exact(rpc, cfg, state, stage)


if __name__ == "__main__":
    unittest.main()
