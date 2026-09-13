#!/usr/bin/env python3
"""Focused C1F1/MNP2 service-boundary qualification."""

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from swap import veld_c1_reservationd as reservationd
from swap import veld_mintd as mintd
from swap import veld_signerd as signerd
from swap.btcveld_c1 import allocation_commitment


ISSUER = "V" + "3" * 33
RECIPIENT = "V" + "2" * 33
ALLOCATION_ID = "0" * 31 + "1"
REQUEST_ID = "12" * 16
SCRIPT = "5120" + "11" * 32
BLIND = "22" * 32
OUTPOINT = "aa" * 32 + ":0"
REAL_TRUE = str(Path("/bin/true").resolve())


def unsigned_proposal(txid, vout=0):
    raw = (1).to_bytes(4, "little") + b"\x01"
    raw += bytes.fromhex(txid) + int(vout).to_bytes(4, "little")
    raw += b"\x00" + b"\xff\xff\xff\xff"
    raw += b"\x01" + (0).to_bytes(8, "little") + b"\x01\x6a"
    raw += b"\x00" * 4
    return raw.hex()


def allocation(sequence=1):
    allocation_id = "%032x" % sequence
    return {
        "request_id": REQUEST_ID,
        "principal_hash": "33" * 32,
        "veld_address": RECIPIENT,
        "amount_sats": 10_000,
        "descriptor_index": 1000,
        "btc_address": "bc1p" + "q" * 58,
        "script_pubkey": SCRIPT,
        "commitment_blind": BLIND,
        "consensus_allocation_id": allocation_id,
        "admitted_at": 1,
        "expires_at": 1 + 7 * 24 * 60 * 60,
        "capacity_policy_sha256": "44" * 32,
    }


def reservation_status(tip=200, *, exposed=True, funded=False,
                       reserve_confirmations=101,
                       exposure_confirmations=101, sequence=1,
                       last_sequence=None, found=True, retired=False):
    allocation_id = "%032x" % sequence
    if last_sequence is None:
        last_sequence = sequence
    return {
        "allocation_id": allocation_id,
        "found": found,
        "active": found and not retired,
        "retired": retired,
        "last_sequence": last_sequence,
        "sequence_history_count": last_sequence,
        "recipient": RECIPIENT,
        "amount_sats": 10_000,
        "allocation_commitment": allocation_commitment(
            allocation_id, RECIPIENT, 10_000, SCRIPT, BLIND),
        "exposed": exposed if found else False,
        "funded": funded if found else False,
        "funding_outpoint": OUTPOINT if funded else None,
        "reserve_canonical_depth_reached": reserve_confirmations >= 101,
        "reserve_confirmations": reserve_confirmations,
        "exposure_canonical_depth_reached": exposed and
            exposure_confirmations >= 101,
        "exposure_confirmations": exposure_confirmations if exposed else None,
        "funding_starts_height": 201 if exposed else None,
        "funding_accepts_through_height": 300 if exposed else None,
        "tip": tip,
    }


def unconsumed_status(root="55" * 32, count=7, proof_hex="00" * 32,
                      tip=200):
    return {
        "outpoint": OUTPOINT,
        "consumed": False,
        "minted": False,
        "proof_hex": proof_hex,
        "root": root,
        "count": count,
        "tip": tip,
    }


class Rpc:
    def __init__(self, reserve, mint=None):
        self.reserve = reserve
        self.mint = mint or unconsumed_status(tip=reserve.get("tip", 200))

    def call(self, method, params=None):
        if method == "getbtcveldc1reservation":
            return dict(self.reserve)
        if method == "getbtcveldmintstatus":
            return dict(self.mint)
        raise AssertionError("unexpected RPC " + method)


class SignerBoundaryTests(unittest.TestCase):
    def peg(self, tip=200):
        return {
            "tip": tip, "supply_sats": 0,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 10_000,
            "issuer_mint_headroom_sats": 90_000,
        }

    def funding(self):
        return {
            "outpoint": OUTPOINT,
            "proof_hex": "43465031" + "00" * 83 + "00" * 32,
            "proof_parent_root": "55" * 32,
            "proof_parent_count": 7,
        }

    def boundary(self, status, phase, funding=None, retry_txid=None, mint=None,
                 claim=None):
        with mock.patch.object(
                signerd, "validate_compiled_mint_policy",
                side_effect=[self.peg(status["tip"]),
                             self.peg(status["tip"])]):
            return signerd.validate_c1_signing_boundary(
                Rpc(status, mint), ISSUER, claim or allocation(), phase,
                funding=funding, retry_txid=retry_txid)

    def test_exposure_depth_100_101_and_funding_window_edges(self):
        with self.assertRaisesRegex(ValueError, "exposure authority"):
            self.boundary(reservation_status(
                exposed=False, reserve_confirmations=100), "EXPOSE")
        self.assertTrue(self.boundary(reservation_status(
            exposed=False, reserve_confirmations=101), "EXPOSE"))

        funding = self.funding()
        with self.assertRaisesRegex(ValueError, "outside"):
            self.boundary(reservation_status(tip=199), "FUND", funding)
        self.assertTrue(self.boundary(
            reservation_status(tip=200), "FUND", funding))
        self.assertTrue(self.boundary(
            reservation_status(tip=299), "FUND", funding))
        with self.assertRaisesRegex(ValueError, "outside"):
            self.boundary(reservation_status(tip=300), "FUND", funding)

    def test_fund_parent_change_and_depth_100_reorg_refuse(self):
        funding = self.funding()
        with self.assertRaisesRegex(ValueError, "proof parent"):
            self.boundary(reservation_status(), "FUND", funding,
                          mint=unconsumed_status(root="66" * 32))
        with self.assertRaisesRegex(ValueError, "deep exposed"):
            self.boundary(reservation_status(exposure_confirmations=100),
                          "FUND", funding)

    def test_every_c1_phase_binds_status_tip_to_both_capacity_samples(self):
        for phase in ("RESERVE", "EXPOSE", "CANCEL", "FUND"):
            with self.subTest(phase=phase), mock.patch.object(
                    signerd, "validate_compiled_mint_policy",
                    side_effect=[self.peg(200), self.peg(200)]):
                with self.assertRaisesRegex(ValueError, "tip differs"):
                    signerd.validate_c1_signing_boundary(
                        Rpc(reservation_status(tip=201)), ISSUER,
                        allocation(), phase,
                        funding=(self.funding() if phase == "FUND" else None))

        with mock.patch.object(
                signerd, "validate_compiled_mint_policy",
                side_effect=[self.peg(200), self.peg(201)]):
            with self.assertRaisesRegex(ValueError, "capacity changed"):
                signerd.validate_c1_signing_boundary(
                    Rpc(reservation_status(tip=200)), ISSUER,
                    allocation(), "EXPOSE")

    def test_sequence_n_minus_one_n_n_plus_one_boundaries(self):
        for phase in ("RESERVE", "CANCEL"):
            for sequence, accepted in ((1, False), (2, True), (3, False)):
                with self.subTest(phase=phase, sequence=sequence):
                    status = reservation_status(
                        sequence=sequence, last_sequence=1, found=False)
                    if accepted:
                        self.assertTrue(self.boundary(
                            status, phase, claim=allocation(sequence)))
                    else:
                        with self.assertRaisesRegex(ValueError, "next"):
                            self.boundary(
                                status, phase, claim=allocation(sequence))

        for phase in ("EXPOSE", "FUND"):
            for sequence, accepted in ((1, True), (2, True), (3, False)):
                with self.subTest(phase=phase, sequence=sequence):
                    status = reservation_status(
                        sequence=sequence, last_sequence=2,
                        exposed=(phase == "FUND"))
                    funding = self.funding() if phase == "FUND" else None
                    if accepted:
                        self.assertTrue(self.boundary(
                            status, phase, funding=funding,
                            claim=allocation(sequence)))
                    else:
                        with self.assertRaisesRegex(ValueError, "high-water"):
                            self.boundary(
                                status, phase, funding=funding,
                                claim=allocation(sequence))

    def test_proofless_mnp2_decoding_binds_blind(self):
        decoded = {
            "from": ISSUER, "to": RECIPIENT, "sats": 10_000,
            "total_out_sats": 99_000,
            "memo": "MNP2;%s;%s;%s;%s" %
                    (ALLOCATION_ID, SCRIPT, BLIND, OUTPOINT),
        }
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(decoded), stderr="")
        with mock.patch.object(signerd, "run_bounded_subprocess",
                               return_value=completed):
            result = signerd.mint_params_from_tx("00", ISSUER, "00")
        self.assertEqual(result[3:],
                         (OUTPOINT, None, ALLOCATION_ID, SCRIPT, BLIND))

    def test_only_cancel_fund_and_mnp2_use_completion_gate(self):
        cases = {
            "RESERVE": (reservation_status(
                exposed=False, found=False, last_sequence=0), None),
            "EXPOSE": (reservation_status(exposed=False), None),
            "CANCEL": (reservation_status(
                exposed=False, found=False, last_sequence=0), None),
            "FUND": (reservation_status(), self.funding()),
        }
        for phase, (status, funding) in cases.items():
            with self.subTest(phase=phase), mock.patch.object(
                    signerd, "validate_compiled_mint_policy",
                    side_effect=[self.peg(status["tip"]),
                                 self.peg(status["tip"])]) as gate:
                signerd.validate_c1_signing_boundary(
                    Rpc(status), ISSUER, allocation(), phase,
                    funding=funding)
                expected = phase in ("CANCEL", "FUND")
                self.assertEqual(
                    [call.kwargs.get("completion")
                     for call in gate.call_args_list],
                    [expected, expected])


class CompletionExceptionServiceTests(unittest.TestCase):
    @staticmethod
    def peg(*, unlocked=True, mint_live=True, completion_live=True):
        return {
            "active": True, "peg_unlocked": unlocked,
            "mint_live": mint_live, "completion_live": completion_live,
            "issuer": ISSUER,
            "issuer_max_per_mint_sats": signerd.MAX_SINGLE_SATS,
            "issuer_static_custody_cap_sats": max(
                signerd.MAX_WINDOW_SATS, 100_000),
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_mint_headroom_sats": 90_000,
        }

    class PegRpc:
        def __init__(self, peg):
            self.peg = peg

        def call(self, method, params=None):
            if method == "getpeginfo":
                return dict(self.peg)
            raise AssertionError(method)

    def test_later_stall_opens_completion_but_not_new_mint_admission(self):
        stalled = self.PegRpc(self.peg(
            mint_live=False, completion_live=True))
        with self.assertRaisesRegex(ValueError, "minting closed"):
            signerd.validate_compiled_mint_policy(
                stalled, ISSUER, completion=False)
        self.assertEqual(signerd.validate_compiled_mint_policy(
            stalled, ISSUER, completion=True)["completion_live"], True)
        self.assertFalse(reservationd.mint_lifecycle_live(stalled))
        self.assertTrue(reservationd.completion_lifecycle_live(stalled))

    def test_prelaunch_rejects_both_admission_and_completion(self):
        prelaunch = self.PegRpc(self.peg(
            unlocked=False, mint_live=False, completion_live=False))
        for completion in (False, True):
            with self.subTest(completion=completion), self.assertRaises(
                    ValueError):
                signerd.validate_compiled_mint_policy(
                    prelaunch, ISSUER, completion=completion)
        self.assertFalse(reservationd.mint_lifecycle_live(prelaunch))
        self.assertFalse(reservationd.completion_lifecycle_live(prelaunch))

    def test_mint_receipt_binds_consensus_id_not_private_request_id(self):
        claim = {
            "request_id": REQUEST_ID, "consensus_allocation_id": ALLOCATION_ID,
            "descriptor_index": 1000, "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": SCRIPT, "deposit_outpoint": OUTPOINT,
            "capacity_policy_sha256": "44" * 32,
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
        }
        heartbeat = {"seq": 3, "tip": 20, "tip_hash": "55" * 32,
                     "headroom_sats": 10_000}
        receipt = {
            "issuer_id": ISSUER, "witness_id": "witness-1",
            "request_id": "66" * 32, "unsigned_tx_sha256": "77" * 32,
            "sats": 10_000, "recipient": RECIPIENT,
            "beat_seq": 3, "tip": 20, "tip_hash": "55" * 32,
            "headroom_sats": 10_000, "allocation_verified": True,
            "allocation_request_id": ALLOCATION_ID,
            "allocation_descriptor_index": 1000,
            "allocation_btc_address": claim["btc_address"],
            "allocation_script_pubkey": SCRIPT,
            "deposit_outpoint": OUTPOINT,
            "allocation_capacity_policy_sha256": "44" * 32,
            "allocation_public_descriptor_range_start": 1000,
            "allocation_public_descriptor_range_end": 10999,
            "sig": "00",
        }
        with mock.patch.object(signerd.sol, "validate_reservation_receipt",
                               return_value=(True, "ok")), \
                mock.patch.object(signerd, "_secure_text", return_value="00"), \
                mock.patch.object(signerd, "run_bounded_subprocess",
                                  return_value=mock.Mock(returncode=0)):
            self.assertIs(signerd.verify_reservation_receipt(
                receipt, ISSUER, {"witness_id": "witness-1"},
                receipt["request_id"], receipt["unsigned_tx_sha256"],
                10_000, RECIPIENT, heartbeat, claim), receipt)
            swapped = dict(receipt, allocation_request_id=REQUEST_ID)
            with self.assertRaisesRegex(ValueError, "allocation_request_id"):
                signerd.verify_reservation_receipt(
                    swapped, ISSUER, {"witness_id": "witness-1"},
                    receipt["request_id"], receipt["unsigned_tx_sha256"],
                    10_000, RECIPIENT, heartbeat, claim)


class Cfp1ProducerTests(unittest.TestCase):
    def legacy_funding_tx(self):
        return (struct.pack("<I", 2) + b"\x01" + b"\x00" * 32 +
                struct.pack("<I", 0xffffffff) + b"\x00" +
                struct.pack("<I", 0xffffffff) + b"\x01" +
                struct.pack("<Q", 10_000) + bytes([34]) +
                bytes.fromhex(SCRIPT) + struct.pack("<I", 0))

    def test_builds_exact_cfp1_and_rechecks_parent(self):
        raw = self.legacy_funding_tx()
        txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        block_hash = "77" * 32

        class Bitcoin:
            def call(self, method, *args):
                if method == "getrawtransaction" and args[1] == "true":
                    return {"txid": txid, "blockhash": block_hash,
                            "confirmations": 7}
                if method == "getrawtransaction":
                    return raw.hex()
                if method == "getblockheader":
                    return {"hash": block_hash, "height": 100,
                            "confirmations": 7}
                if method == "getblockhash":
                    return block_hash
                if method == "getblock":
                    return {"hash": block_hash, "height": 100,
                            "merkleroot": txid, "tx": [txid]}
                raise AssertionError("unexpected Bitcoin RPC " + method)

        class Veld:
            def rpc(self, method, params=None):
                if method == "getbtcheaderinfo":
                    return {"spv_active": True, "k_btc": 6,
                            "best_height": 106}
                raise AssertionError("unexpected Veld RPC " + method)

        daemon = object.__new__(mintd.Minter)
        daemon.production = True
        daemon.K_BTC = 6
        daemon.btc = Bitcoin()
        daemon.veld = Veld()
        parent = {
            "consumed": False, "minted": False,
            "proof_hex": "00" * 32, "root": "55" * 32, "count": 7,
        }
        daemon.mint_outpoint_status = mock.Mock(
            side_effect=[dict(parent), dict(parent)])
        claim = allocation()
        deposit = {"txid": txid, "vout": 0, "sats": 10_000}
        proof = daemon._build_c1_funding_proof(deposit, claim)
        self.assertEqual(proof["outpoint"], txid + ":0")
        self.assertTrue(bytes.fromhex(proof["proof_hex"]).startswith(b"CFP1"))
        self.assertTrue(proof["proof_hex"].endswith(parent["proof_hex"]))
        self.assertEqual(proof["proof_parent_root"], parent["root"])

        changed = dict(parent, root="66" * 32)
        daemon.mint_outpoint_status = mock.Mock(
            side_effect=[dict(parent), changed])
        with self.assertRaisesRegex(RuntimeError, "root changed"):
            daemon._build_c1_funding_proof(deposit, claim)

        daemon.mint_outpoint_status = mock.Mock(
            side_effect=[dict(parent), dict(parent)])
        original_call = daemon.btc.call
        height_reads = 0

        def reorg(method, *args):
            nonlocal height_reads
            if method == "getblockhash":
                height_reads += 1
                if height_reads == 2:
                    return "88" * 32
            return original_call(method, *args)

        daemon.btc.call = reorg
        with self.assertRaisesRegex(RuntimeError, "reorged"):
            daemon._build_c1_funding_proof(deposit, claim)


class TerminalArchiveTests(unittest.TestCase):
    def record(self):
        return {
            "kind": "active", "allocation_sha256": "88" * 32,
            "request_id": REQUEST_ID, "terminal_observed_tip": None,
            "RESERVE": None, "EXPOSE": None, "CANCEL": None, "FUND": [],
        }

    def test_worm_ack_precedes_terminal_local_deletion(self):
        record = self.record()
        state = {"version": 3, "sequence": 0,
                 "records": {ALLOCATION_ID: record}}
        cfg = {"terminal_archive_command": ("/archive",)}
        status = {"tip": 100}
        with mock.patch.object(reservationd, "persist") as persist:
            self.assertFalse(reservationd.compact_terminal(
                mock.Mock(), cfg, state, ALLOCATION_ID, record, status))
            persist.assert_called_once()
        self.assertEqual(record["terminal_observed_tip"], 100)

        digest = hashlib.sha256(
            reservationd.canonical(record).encode()).hexdigest()
        answer = {"version": 1, "archived": True,
                  "allocation_id": ALLOCATION_ID,
                  "record_sha256": digest, "readback_sha256": digest,
                  "archive_id": "worm/object/1",
                  "object_lock_mode": "COMPLIANCE",
                  "retention_until": 3_000_000_000}
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(answer), stderr="")
        with mock.patch.object(reservationd, "run_bounded_subprocess",
                               return_value=completed), \
                mock.patch.object(reservationd, "persist") as persist:
            self.assertTrue(reservationd.compact_terminal(
                mock.Mock(), cfg, state, ALLOCATION_ID, record, {"tip": 200}))
            self.assertNotIn(ALLOCATION_ID, state["records"])
            persist.assert_called_once()

    def test_archive_refusal_retains_full_record(self):
        record = self.record()
        record["terminal_observed_tip"] = 1
        state = {"version": 3, "sequence": 0,
                 "records": {ALLOCATION_ID: record}}
        completed = subprocess.CompletedProcess(
            [], 9, stdout="", stderr="no quorum")
        with mock.patch.object(reservationd, "run_bounded_subprocess",
                               return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "archive refused"):
                reservationd.compact_terminal(
                    mock.Mock(), {"terminal_archive_command": ("/archive",)},
                    state, ALLOCATION_ID, record, {"tip": 101})
        self.assertIs(state["records"][ALLOCATION_ID], record)
        self.assertIn("FUND", record)

    def test_terminal_observation_reorg_clear_is_transactional(self):
        record = self.record()
        record["terminal_observed_tip"] = 100
        state = {"version": 3, "sequence": 7,
                 "records": {ALLOCATION_ID: record}}
        with mock.patch.object(reservationd, "persist") as persist:
            self.assertTrue(reservationd.clear_terminal_observation(
                {}, state, record))
            persist.assert_called_once()
        self.assertIsNone(record["terminal_observed_tip"])

        record["terminal_observed_tip"] = 200
        with mock.patch.object(reservationd, "persist",
                               side_effect=RuntimeError("checkpoint down")):
            with self.assertRaisesRegex(RuntimeError, "checkpoint down"):
                reservationd.clear_terminal_observation({}, state, record)
        self.assertEqual(record["terminal_observed_tip"], 200)


class SignerCacheDurabilityTests(unittest.TestCase):
    def raw_record(self):
        signed_hex = "03" * 100
        return {
            "kind": "raw", "allocation_sha256": "66" * 32,
            "unsigned_sha256": "77" * 32, "signed_tx_hex": signed_hex,
            "txid": hashlib.sha256(hashlib.sha256(
                bytes.fromhex(signed_hex)).digest()).hexdigest(),
            "signed_at": 10, "funding_sha256": None,
            "semantic_sha256": None,
            "input_outpoints": ["90" * 32 + ":0"],
        }

    def receipt(self, record):
        return {
            "version": 1, "action": "ack_c1_signature_durable",
            "allocation_id": ALLOCATION_ID, "phase": "RESERVE",
            "funding_sha256": None,
            "allocation_sha256": record["allocation_sha256"],
            "unsigned_sha256": record["unsigned_sha256"],
            "signed_tx_sha256": hashlib.sha256(
                bytes.fromhex(record["signed_tx_hex"])).hexdigest(),
            "txid": record["txid"], "coordinator_sequence": 7,
            "coordinator_state_sha256": "88" * 32,
        }

    @staticmethod
    def archive_result(invocation):
        request = json.loads(invocation.kwargs["input_text"])
        digest = request["record_sha256"]
        return subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "version": 1, "archived": True,
            "allocation_id": request["allocation_id"],
            "record_sha256": digest, "readback_sha256": digest,
            "archive_id": "worm/signer/" + digest[:16],
            "object_lock_mode": "COMPLIANCE",
            "retention_until": 3_000_000_000,
        }), stderr="")

    def cfg(self):
        return {"c1_reservation_authority": {
            "enabled": True, "allocation_witness_command": [REAL_TRUE],
            "durable_archive_command": [REAL_TRUE],
        }}

    def test_coordinator_receipt_archives_before_dropping_raw_bytes(self):
        record = self.raw_record()
        key = ALLOCATION_ID + ":RESERVE"
        state = signerd._empty_c1_signer_state()
        state["records"][key] = record

        def archive(*args, **kwargs):
            return self.archive_result(mock.Mock(kwargs=kwargs))

        with mock.patch.object(signerd, "load_c1_signer_state",
                               return_value=state), \
                mock.patch.object(signerd, "save_c1_signer_state") as save, \
                mock.patch.object(signerd, "run_bounded_subprocess",
                                  side_effect=archive):
            answer = signerd.acknowledge_c1_signature_durable(
                self.receipt(record), self.cfg())
            self.assertFalse(answer["idempotent"])
            save.assert_called_once_with(state)
        self.assertEqual(state["records"][key]["kind"], "durable")
        self.assertNotIn("signed_tx_hex", state["records"][key])

        with mock.patch.object(signerd, "load_c1_signer_state",
                               return_value=state), \
                mock.patch.object(signerd, "run_bounded_subprocess") as archive:
            answer = signerd.acknowledge_c1_signature_durable(
                self.receipt(record), self.cfg())
        self.assertTrue(answer["idempotent"])
        archive.assert_not_called()

    def test_weak_worm_ack_never_drops_only_raw_copy(self):
        record = self.raw_record()
        key = ALLOCATION_ID + ":RESERVE"
        state = signerd._empty_c1_signer_state()
        state["records"][key] = record
        weak = subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "version": 1, "archived": True, "allocation_id": ALLOCATION_ID,
            "record_sha256": "00" * 32, "readback_sha256": "00" * 32,
            "archive_id": "weak", "object_lock_mode": "GOVERNANCE",
            "retention_until": 3_000_000_000,
        }), stderr="")
        with mock.patch.object(signerd, "load_c1_signer_state",
                               return_value=state), \
                mock.patch.object(signerd, "save_c1_signer_state") as save, \
                mock.patch.object(signerd, "run_bounded_subprocess",
                                  return_value=weak):
            with self.assertRaisesRegex(RuntimeError, "not exact/durable"):
                signerd.acknowledge_c1_signature_durable(
                    self.receipt(record), self.cfg())
        self.assertIs(state["records"][key], record)
        save.assert_not_called()

    def durable_record(self):
        raw = self.raw_record()
        return {
            "kind": "durable", "allocation_sha256": raw["allocation_sha256"],
            "unsigned_sha256": raw["unsigned_sha256"],
            "signed_tx_sha256": hashlib.sha256(
                bytes.fromhex(raw["signed_tx_hex"])).hexdigest(),
            "txid": raw["txid"], "signed_at": raw["signed_at"],
            "funding_sha256": None, "semantic_sha256": None,
            "input_outpoints": raw["input_outpoints"],
            "archive_record_sha256": "99" * 32,
            "archive_id": "worm/stage/1", "archived_at": 11,
            "coordinator_sequence": 7,
            "coordinator_state_sha256": "88" * 32,
        }

    def test_terminal_compaction_waits_101_and_resets_on_rollback(self):
        key = ALLOCATION_ID + ":RESERVE"
        state = signerd._empty_c1_signer_state()
        state["records"][key] = self.durable_record()

        class Rpc:
            def __init__(self, retired, tip):
                self.retired, self.tip = retired, tip

            def call(self, method, params=None):
                return {"allocation_id": ALLOCATION_ID,
                        "retired": self.retired, "tip": self.tip}

        with mock.patch.object(signerd, "save_c1_signer_state"):
            self.assertEqual(signerd.compact_c1_signer_state(
                Rpc(True, 100), self.cfg(), state), 0)
            self.assertEqual(state["terminal_observations"][ALLOCATION_ID], 100)
            self.assertEqual(signerd.compact_c1_signer_state(
                Rpc(False, 101), self.cfg(), state), 0)
            self.assertNotIn(ALLOCATION_ID, state["terminal_observations"])
            self.assertIn(key, state["records"])
            self.assertEqual(signerd.compact_c1_signer_state(
                Rpc(True, 200), self.cfg(), state), 0)
            with mock.patch.object(signerd, "run_bounded_subprocess",
                                   side_effect=lambda *a, **kw:
                                   self.archive_result(mock.Mock(kwargs=kw))):
                self.assertEqual(signerd.compact_c1_signer_state(
                    Rpc(True, 300), self.cfg(), state), 1)
        self.assertNotIn(key, state["records"])
        self.assertNotIn(ALLOCATION_ID, state["tombstones"])

    def test_state_roundtrip_and_symmetric_size_ceiling(self):
        state = signerd._empty_c1_signer_state()
        state["records"][ALLOCATION_ID + ":RESERVE"] = self.raw_record()
        for sequence in range(2, 513):
            state["records"]["%032x:RESERVE" % sequence] = \
                self.durable_record()
        with tempfile.TemporaryDirectory(prefix="c1-signer-state-") as directory:
            Path(directory).chmod(0o700)
            path = str(Path(directory) / "state.json")
            with mock.patch.object(signerd, "C1_STATEF", path):
                signerd.save_c1_signer_state(state)
                self.assertEqual(signerd.load_c1_signer_state(), state)
                with mock.patch.object(signerd, "C1_STATE_MAX_BYTES", 128):
                    with self.assertRaisesRegex(ValueError, "byte ceiling"):
                        signerd.save_c1_signer_state(state)


class CapacityReserveTests(unittest.TestCase):
    def test_new_lifecycle_uses_90_percent_reserve_completion_uses_hard_cap(self):
        signer_state = signerd._empty_c1_signer_state()
        signer_size = signerd.c1_signer_state_size(signer_state)
        with mock.patch.object(signerd, "C1_STATE_RESERVE_BYTES",
                               signer_size + 10):
            signerd.require_c1_signer_lifecycle_capacity(signer_state, 10)
            with self.assertRaisesRegex(ValueError, "admission reserve"):
                signerd.require_c1_signer_lifecycle_capacity(signer_state, 11)

        coordinator_state = {"version": 3, "sequence": 0, "records": {}}
        projected = reservationd.projected_state_size(coordinator_state)
        with mock.patch.object(reservationd, "STATE_ADMISSION_MAX", projected):
            reservationd.require_lifecycle_admission_capacity(coordinator_state)
            with self.assertRaisesRegex(ValueError, "admission reserve"):
                reservationd.require_lifecycle_admission_capacity(
                    coordinator_state, 1)

    def test_cached_exposure_never_rebroadcasts_while_mint_gate_closed(self):
        stage = {"signed_tx_hex": "00"}
        rpc = mock.Mock()
        with mock.patch.object(reservationd, "mint_lifecycle_live",
                               return_value=False), \
                mock.patch.object(reservationd, "broadcast_exact") as broadcast:
            self.assertFalse(reservationd.rebroadcast_cached_exposure_if_live(
                rpc, {}, {}, stage))
            broadcast.assert_not_called()
        with mock.patch.object(reservationd, "mint_lifecycle_live",
                               return_value=True), \
                mock.patch.object(reservationd, "broadcast_exact",
                                  return_value=True) as broadcast:
            self.assertTrue(reservationd.rebroadcast_cached_exposure_if_live(
                rpc, {}, {}, stage))
            broadcast.assert_called_once_with(rpc, {}, {}, stage)

    def test_hard_cap_failure_rolls_back_in_memory_lifecycle_mutation(self):
        claim = allocation()
        record = {
            "kind": "active", "allocation_sha256": "aa" * 32,
            "request_id": REQUEST_ID, "terminal_observed_tip": None,
            "RESERVE": None, "EXPOSE": None, "CANCEL": None, "FUND": [],
        }
        state = {"version": 3, "sequence": 4,
                 "records": {ALLOCATION_ID: record}}
        prepared = {
            "allocation_id": ALLOCATION_ID, "action": "EXPOSE",
            "recipient": RECIPIENT, "amount_sats": 10_000,
            "allocation_commitment": allocation_commitment(
                ALLOCATION_ID, RECIPIENT, 10_000, SCRIPT, BLIND),
            "required_confirmations": 101, "lifetime_blocks": 7 * 480,
            "fee": 100_000,
            "unsigned_tx_hex": unsigned_proposal("90" * 32),
            "excluded_issuer_prevouts": [],
        }
        rpc = mock.Mock()
        rpc.call.return_value = prepared
        with mock.patch.object(reservationd, "persist",
                               side_effect=ValueError("byte ceiling")):
            with self.assertRaisesRegex(ValueError, "byte ceiling"):
                reservationd.prepare_stage(
                    rpc, {"issuer": ISSUER}, claim, "EXPOSE", record, state)
        self.assertIsNone(record["EXPOSE"])
        self.assertEqual(state["sequence"], 4)

    def test_deleted_terminal_is_not_recreated_and_missing_active_fails(self):
        state = {"version": 3, "sequence": 9, "records": {}}
        retired = {"retired": True, "found": False}
        with mock.patch.object(reservationd, "persist") as persist:
            self.assertIsNone(reservationd.bind_or_admit_record(
                {}, state, allocation(), retired))
            persist.assert_not_called()
        self.assertEqual(state["records"], {})

        with self.assertRaisesRegex(ValueError, "missing durable"):
            reservationd.bind_or_admit_record(
                {}, state, allocation(), {"retired": False, "found": True})
        self.assertEqual(state["records"], {})

        # The isolated signer independently samples the same lifetime
        # authority, so deletion of its local archived row cannot reauthorize
        # an old sequence.
        with self.assertRaisesRegex(ValueError, "exactly next"):
            SignerBoundaryTests().boundary(
                reservation_status(found=False, retired=True,
                                   last_sequence=1),
                "RESERVE", claim=allocation())


class CrossCapabilityPrevoutLeaseTests(unittest.TestCase):
    def test_conflict_is_durably_revoked_and_fresh_unsigned_can_replace_it(self):
        state = signerd._empty_prevout_journal()
        c1_unsigned = unsigned_proposal("91" * 32)
        mint_conflict = unsigned_proposal("91" * 32)
        mint_fresh = unsigned_proposal("92" * 32)
        c1_owner = signerd.c1_prevout_owner_id(ALLOCATION_ID, "RESERVE")
        mint_owner = signerd.mint_prevout_owner_id(ALLOCATION_ID)
        with mock.patch.object(signerd, "save_prevout_journal") as save:
            signerd.reserve_issuer_prevouts(
                state, c1_owner, "c1-reservation", ALLOCATION_ID, None,
                c1_unsigned)
            with self.assertRaises(signerd.UnsignedCarrierAbandoned) as caught:
                signerd.reject_conflicting_issuer_prevouts(
                    state, mint_owner, "mint", ALLOCATION_ID, OUTPOINT,
                    mint_conflict)
            answer = caught.exception.answer
            self.assertEqual(answer["owner_id"], mint_owner)
            self.assertEqual(answer["deposit_outpoint"], OUTPOINT)
            self.assertEqual(answer["unsigned_sha256"], hashlib.sha256(
                bytes.fromhex(mint_conflict)).hexdigest())
            self.assertEqual(answer["conflicting_input_outpoints"],
                             ["91" * 32 + ":0"])
            self.assertEqual(save.call_count, 2)

            # A lost exit-75 reply is harmless: the same hash can never reach
            # the key, while a different non-conflicting template may lease.
            with self.assertRaises(signerd.UnsignedCarrierAbandoned):
                signerd.reject_conflicting_issuer_prevouts(
                    state, mint_owner, "mint", ALLOCATION_ID, OUTPOINT,
                    mint_conflict)
            signerd.reject_conflicting_issuer_prevouts(
                state, mint_owner, "mint", ALLOCATION_ID, OUTPOINT,
                mint_fresh)
            lease, created = signerd.reserve_issuer_prevouts(
                state, mint_owner, "mint", ALLOCATION_ID, OUTPOINT,
                mint_fresh)
            self.assertTrue(created)
            self.assertIsNone(lease["txid"])
            signerd.mark_issuer_prevout_signature(
                state, mint_owner, mint_fresh, "ab" * 32)
            self.assertEqual(state["owners"][mint_owner]["active"]["txid"],
                             "ab" * 32)

    def test_minter_discards_only_exact_exit_75_unsigned_attestation(self):
        oid = OUTPOINT
        record = {"status": "prepared", "recipient": RECIPIENT,
                  "sats": 10_000, "at": 1, "unsigned_tx_hex": "00",
                  "inputs": [], "signer_allocation": {}}
        daemon = object.__new__(mintd.Minter)
        daemon.ledger = {oid: record}
        exact_prepared = dict(record)
        daemon.signer = mock.Mock()
        daemon.signer.sign.side_effect = \
            mintd.UnsignedMintCarrierAbandoned(["91" * 32 + ":0"])
        daemon._save_record = mock.Mock()
        self.assertFalse(daemon._advance_unresolved(oid, record))
        self.assertEqual(daemon.ledger[oid], {
            "status": "reprepare", "recipient": RECIPIENT,
            "sats": 10_000, "at": 1,
            "excluded_issuer_prevouts": ["91" * 32 + ":0"],
        })
        daemon._save_record.assert_called_once()

        record = exact_prepared
        daemon.ledger[oid] = record
        daemon.signer.sign.side_effect = RuntimeError("lost SSH reply")
        with self.assertRaisesRegex(RuntimeError, "lost SSH"):
            daemon._advance_unresolved(oid, record)
        self.assertIs(daemon.ledger[oid], record)

    def test_coordinator_replaces_only_signer_revoked_unsigned_stage(self):
        claim = allocation()
        unsigned = unsigned_proposal("91" * 32)
        stage = {
            "unsigned_tx_hex": unsigned,
            "unsigned_sha256": hashlib.sha256(
                bytes.fromhex(unsigned)).hexdigest(),
            "signed_tx_hex": None, "txid": None,
            "broadcast_attempts": 0, "last_broadcast_at": None,
            "funding_sha256": None, "semantic_sha256": None,
            "funding_outpoint": None, "created_at": 1,
            "signer_archive_record_sha256": None,
            "signer_archive_id": None, "signer_receipt_sequence": None,
            "signer_receipt_state_sha256": None,
        }
        exact_stage = dict(stage)
        record = {"kind": "active", "allocation_sha256": "44" * 32,
                  "request_id": REQUEST_ID, "terminal_observed_tip": None,
                  "RESERVE": stage, "EXPOSE": None, "CANCEL": None,
                  "FUND": []}
        state = {"version": 4, "sequence": 1,
                 "records": {ALLOCATION_ID: record},
                 "compaction_cursor": None}
        answer = {
            "version": 1, "action": "unsigned_carrier_abandoned",
            "capability": "c1-reservation",
            "owner_id": "c1:" + ALLOCATION_ID + ":RESERVE",
            "allocation_id": ALLOCATION_ID, "deposit_outpoint": None,
            "unsigned_sha256": stage["unsigned_sha256"],
            "conflicting_input_outpoints": ["91" * 32 + ":0"],
            "reason": "issuer_prevout_conflict",
        }
        completed = subprocess.CompletedProcess(
            [], 75, stdout=json.dumps(answer), stderr="")
        cfg = {"reservation_signer_command": ("/sign",)}
        with mock.patch.object(reservationd, "run_bounded_subprocess",
                               return_value=completed), \
                mock.patch.object(reservationd, "persist") as persist:
            with self.assertRaisesRegex(RuntimeError, "fresh preparation"):
                reservationd.prepare_stage(
                    mock.Mock(), cfg, claim, "RESERVE", record, state)
            persist.assert_called_once()
        self.assertIs(record["RESERVE"], stage)
        self.assertTrue(stage["replacement_required"])
        self.assertEqual(stage["excluded_issuer_prevouts"],
                         ["91" * 32 + ":0"])

        stage = exact_stage
        record["RESERVE"] = stage
        refused = subprocess.CompletedProcess([], 2, stdout="", stderr="no")
        with mock.patch.object(reservationd, "run_bounded_subprocess",
                               return_value=refused), \
                mock.patch.object(reservationd, "persist"):
            with self.assertRaisesRegex(RuntimeError, "signer refused"):
                reservationd.prepare_stage(
                    mock.Mock(), cfg, claim, "RESERVE", record, state)
        self.assertIs(record["RESERVE"], stage)

    def test_stale_fund_variant_restarts_with_persisted_exclusion_suffix(self):
        claim = allocation()
        funding = SignerBoundaryTests().funding()
        old_unsigned = unsigned_proposal("91" * 32)
        alternate_unsigned = unsigned_proposal("92" * 32)
        funding_sha = reservationd._funding_sha256(funding)
        stage = {
            "unsigned_tx_hex": old_unsigned,
            "unsigned_sha256": hashlib.sha256(
                bytes.fromhex(old_unsigned)).hexdigest(),
            "signed_tx_hex": None, "txid": None,
            "broadcast_attempts": 0, "last_broadcast_at": None,
            "funding_sha256": funding_sha,
            "semantic_sha256": reservationd._funding_semantic_sha256(
                claim, funding),
            "funding_outpoint": funding["outpoint"], "created_at": 1,
            "signer_archive_record_sha256": None,
            "signer_archive_id": None, "signer_receipt_sequence": None,
            "signer_receipt_state_sha256": None,
        }
        record = {
            "kind": "active", "allocation_sha256": "44" * 32,
            "request_id": REQUEST_ID, "terminal_observed_tip": None,
            "RESERVE": None, "EXPOSE": None, "CANCEL": None,
            "FUND": [stage],
        }
        state = {"version": 4, "sequence": 1,
                 "records": {ALLOCATION_ID: record},
                 "compaction_cursor": None}
        abandoned = {
            "version": 1, "action": "unsigned_carrier_abandoned",
            "capability": "c1-reservation",
            "owner_id": "c1:%s:FUND:%s" % (ALLOCATION_ID, funding_sha),
            "allocation_id": ALLOCATION_ID, "deposit_outpoint": None,
            "unsigned_sha256": stage["unsigned_sha256"],
            "conflicting_input_outpoints": ["91" * 32 + ":0"],
            "reason": "issuer_prevout_conflict",
        }
        cfg = {"issuer": ISSUER, "reservation_signer_command": ("/sign",)}
        with mock.patch.object(
                reservationd, "run_bounded_subprocess",
                return_value=subprocess.CompletedProcess(
                    [], 75, stdout=json.dumps(abandoned), stderr="")), \
                mock.patch.object(reservationd, "persist") as persisted:
            with self.assertRaisesRegex(RuntimeError, "fresh preparation"):
                reservationd.prepare_stage(
                    mock.Mock(), cfg, claim, "FUND", record, state,
                    funding=funding)
            persisted.assert_called_once()

        # Model process restart from the fsynced coordinator bytes.
        state = json.loads(json.dumps(state))
        record = state["records"][ALLOCATION_ID]
        stage = record["FUND"][0]
        self.assertTrue(stage["replacement_required"])
        self.assertEqual(stage["excluded_issuer_prevouts"],
                         ["91" * 32 + ":0"])

        prepared = {
            "allocation_id": ALLOCATION_ID, "action": "FUND",
            "recipient": RECIPIENT, "amount_sats": 10_000,
            "allocation_commitment": allocation_commitment(
                ALLOCATION_ID, RECIPIENT, 10_000, SCRIPT, BLIND),
            "required_confirmations": 101,
            "lifetime_blocks": 7 * 480, "fee": 100_000,
            "excluded_issuer_prevouts": ["91" * 32 + ":0"],
            "unsigned_tx_hex": alternate_unsigned,
        }
        signed_hex = "ab" * 80
        signed_answer = {
            "version": 2, "action": "signed_c1_reservation",
            "phase": "FUND", "request_id": REQUEST_ID,
            "allocation_id": ALLOCATION_ID,
            "signed_tx_hex": signed_hex,
            "txid": reservationd.txid(signed_hex),
        }
        rpc = mock.Mock()
        rpc.call.return_value = prepared
        durable = {
            "record_sha256": "aa" * 32, "archive_id": "worm/1",
        }
        with mock.patch.object(
                reservationd, "run_bounded_subprocess",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(signed_answer), stderr="")), \
                mock.patch.object(
                    reservationd.solvency,
                    "unsigned_template_from_signed_hex",
                    return_value=alternate_unsigned), \
                mock.patch.object(
                    reservationd, "persist", return_value="bb" * 32) as persist, \
                mock.patch.object(
                    reservationd, "acknowledge_signer_durable",
                    return_value=durable):
            result = reservationd.prepare_stage(
                rpc, cfg, claim, "FUND", record, state, funding=funding)
        params = rpc.call.call_args.args[1]
        self.assertEqual(params[-1],
                         "issuer-prevout-exclusions-v1:" + "91" * 32 + ":0")
        self.assertFalse(result["replacement_required"])
        self.assertEqual(result["excluded_issuer_prevouts"],
                         ["91" * 32 + ":0"])
        self.assertEqual(result["unsigned_tx_hex"], alternate_unsigned)
        self.assertEqual(result["signed_tx_hex"], signed_hex)
        self.assertGreaterEqual(persist.call_count, 3)

    def test_leases_release_only_after_hash_anchored_terminal_depth_101(self):
        state = signerd._empty_prevout_journal()
        owner = signerd.c1_prevout_owner_id(ALLOCATION_ID, "FUND", "77" * 32)
        with mock.patch.object(signerd, "save_prevout_journal"):
            signerd.reserve_issuer_prevouts(
                state, owner, "c1-reservation", ALLOCATION_ID, None,
                unsigned_proposal("93" * 32))

        class Rpc:
            def __init__(self):
                self.tip = 100
                self.tip_hash = "10" * 32
                self.old_hash = self.tip_hash

            def call(self, method, params=None):
                if method == "getbtcveldsupply":
                    return {"supply_sats": 0, "tip": self.tip,
                            "tip_hash": self.tip_hash}
                if method == "getbtcveldc1reservation":
                    return {"allocation_id": ALLOCATION_ID,
                            "retired": True, "tip": self.tip}
                if method == "getblockhash":
                    return self.old_hash
                raise AssertionError(method)

        rpc = Rpc()
        with mock.patch.object(signerd, "save_prevout_journal"):
            self.assertEqual(signerd.maintain_prevout_journal(rpc, state), 0)
            self.assertIn(owner, state["owners"])
            rpc.tip = 199
            rpc.tip_hash = "20" * 32
            self.assertEqual(signerd.maintain_prevout_journal(rpc, state), 0)
            self.assertIn(owner, state["owners"])
            rpc.tip = 200
            self.assertEqual(signerd.maintain_prevout_journal(rpc, state), 1)
        self.assertNotIn(owner, state["owners"])

    def test_signing_crash_recovers_exact_stage_and_never_resigns_ambiguity(self):
        unsigned = unsigned_proposal("94" * 32)
        signed = "ab" * 80
        owner = signerd.c1_prevout_owner_id(ALLOCATION_ID, "RESERVE")
        with tempfile.TemporaryDirectory(prefix="issuer-stage-") as directory:
            root = Path(directory)
            stage_dir = root / ".staging"
            journal_path = root / "leases.json"
            key = root / "issuer.key"; key.write_text("key"); key.chmod(0o600)
            password = root / "pass"; password.write_text("pw"); password.chmod(0o600)
            keygen = root / "keygen"; keygen.write_text("x"); keygen.chmod(0o700)
            state = signerd._empty_prevout_journal()

            def key_operation(argv, **_kwargs):
                durable = json.loads(journal_path.read_text())
                active = durable["owners"][owner]["active"]
                self.assertEqual(active["signing_state"], "SIGNING")
                output = Path(argv[argv.index("--out") + 1])
                # Simulate keygen's ordinary ofstream under sshd umask 022.
                # The signer must have precreated the inode as 0600.
                prior_umask = __import__("os").umask(0o022)
                try:
                    output.write_text(signed)
                finally:
                    __import__("os").umask(prior_umask)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with mock.patch.multiple(
                    signerd, PREVOUT_STATEF=str(journal_path),
                    SIGNING_STAGE_DIR=str(stage_dir), KEYFILE=str(key),
                    PASSFILE=str(password), KEYGEN=str(keygen)), \
                    mock.patch.object(signerd.sol,
                                      "unsigned_template_from_signed_hex",
                                      return_value=unsigned), \
                    mock.patch.object(signerd, "run_bounded_subprocess",
                                      side_effect=key_operation) as run:
                signerd.reserve_issuer_prevouts(
                    state, owner, "c1-reservation", ALLOCATION_ID, None,
                    unsigned)
                self.assertEqual(signerd.sign_or_recover_staged_carrier(
                    state, owner, unsigned, "00" * 25, "test"), signed)
                self.assertEqual(state["owners"][owner]["active"][
                    "signing_state"], "SIGNING")
                # Crash before the C1/mint cache fsync: restart recovers the
                # deterministic exact output without invoking the key again.
                run.reset_mock()
                self.assertEqual(signerd.sign_or_recover_staged_carrier(
                    state, owner, unsigned, "00" * 25, "test"), signed)
                run.assert_not_called()
                _, signed_path = signerd._signing_stage_paths(
                    state["owners"][owner]["active"]["staging_id"])
                Path(signed_path).unlink()
                with self.assertRaisesRegex(ValueError, "indeterminate"):
                    signerd.sign_or_recover_staged_carrier(
                        state, owner, unsigned, "00" * 25, "test")
                run.assert_not_called()

    def test_staged_signature_accepts_exact_hex_ceiling_plus_newline(self):
        unsigned = unsigned_proposal("9a" * 32)
        signed = "ab" * 80
        owner = signerd.c1_prevout_owner_id(ALLOCATION_ID, "RESERVE")
        with tempfile.TemporaryDirectory(prefix="issuer-stage-boundary-") as directory:
            root = Path(directory)
            key = root / "issuer.key"; key.write_text("key"); key.chmod(0o600)
            password = root / "pass"; password.write_text("pw"); password.chmod(0o600)
            keygen = root / "keygen"; keygen.write_text("x"); keygen.chmod(0o700)
            state = signerd._empty_prevout_journal()

            def key_operation(argv, **_kwargs):
                output = Path(argv[argv.index("--out") + 1])
                output.write_text(signed + "\n")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with mock.patch.multiple(
                    signerd,
                    PREVOUT_STATEF=str(root / "leases.json"),
                    SIGNING_STAGE_DIR=str(root / ".staging"),
                    KEYFILE=str(key), PASSFILE=str(password),
                    KEYGEN=str(keygen)), \
                    mock.patch.object(
                        signerd.sol, "unsigned_template_from_signed_hex",
                        return_value=unsigned), \
                    mock.patch.object(
                        signerd, "run_bounded_subprocess",
                        side_effect=key_operation):
                signerd.reserve_issuer_prevouts(
                    state, owner, "c1-reservation", ALLOCATION_ID, None,
                    unsigned)
                self.assertEqual(signerd.sign_or_recover_staged_carrier(
                    state, owner, unsigned, "00" * 25, "test",
                    maximum_signed_hex_bytes=len(signed)), signed)

    def test_initialized_empty_journal_reconciles_mint_and_archived_c1_union(self):
        mint_unsigned = unsigned_proposal("95" * 32)
        mint_signed = "bc" * 80
        mint_txid = hashlib.sha256(hashlib.sha256(
            bytes.fromhex(mint_signed)).digest()).hexdigest()
        mint_request = hashlib.sha256(
            bytes.fromhex(mint_unsigned)).hexdigest()
        mint_state = {"signed": [{
            "request_id": mint_request, "txid": mint_txid,
            "signed_tx_hex": mint_signed, "sats": 10_000,
            "to": RECIPIENT, "at": 1,
        }]}
        c1_key = "%032x:RESERVE" % 2
        durable = SignerCacheDurabilityTests().durable_record()
        durable.pop("input_outpoints")
        c1_state = signerd._empty_c1_signer_state()
        c1_state["records"][c1_key] = durable
        archived = dict(durable)
        archived["kind"] = "raw"
        for field in ("signed_tx_sha256", "archive_record_sha256", "archive_id",
                      "archived_at", "coordinator_sequence",
                      "coordinator_state_sha256"):
            archived.pop(field, None)
        archived["signed_tx_hex"] = "cd" * 80
        archived["txid"] = hashlib.sha256(hashlib.sha256(
            bytes.fromhex(archived["signed_tx_hex"])).digest()).hexdigest()
        archived["input_outpoints"] = ["96" * 32 + ":0"]
        with tempfile.TemporaryDirectory(prefix="lease-reconcile-") as directory:
            journal = str(Path(directory) / "leases.json")
            with mock.patch.multiple(
                    signerd, PREVOUT_STATEF=journal,
                    SIGNING_STAGE_DIR=str(Path(directory) / ".staging")), \
                    mock.patch.object(signerd, "load_signer_state",
                                      return_value=mint_state), \
                    mock.patch.object(signerd, "load_c1_signer_state",
                                      return_value=c1_state), \
                    mock.patch.object(signerd.sol,
                                      "unsigned_template_from_signed_hex",
                                      return_value=mint_unsigned), \
                    mock.patch.object(signerd, "mint_params_from_tx",
                                      return_value=(
                                          RECIPIENT, 10_000, 1, OUTPOINT, None,
                                          ALLOCATION_ID, SCRIPT, BLIND)), \
                    mock.patch.object(signerd,
                                      "_read_archived_c1_cache_record",
                                      return_value=archived) as readback, \
                    mock.patch.object(signerd, "save_c1_signer_state") as save_c1:
                signerd.save_prevout_journal(signerd._empty_prevout_journal())
                state = signerd.load_or_reconcile_prevout_journal(
                    {}, ISSUER, "00" * 25)
            readback.assert_called_once()
            save_c1.assert_called_once_with(c1_state)
            self.assertEqual(set(state["owners"]), {
                "mint:" + ALLOCATION_ID, "c1:" + c1_key})
            self.assertTrue(all(owner["active"]["signing_state"] == "SIGNED"
                                for owner in state["owners"].values()))
            self.assertTrue(Path(journal).exists())

    def test_terminal_gc_never_deletes_stage_before_lease_removal_fsync(self):
        unsigned = unsigned_proposal("97" * 32)
        owner_id = signerd.c1_prevout_owner_id(ALLOCATION_ID, "RESERVE")
        state = signerd._empty_prevout_journal()
        with tempfile.TemporaryDirectory(prefix="gc-order-") as directory, \
                mock.patch.multiple(
                    signerd,
                    PREVOUT_STATEF=str(Path(directory) / "leases.json"),
                    SIGNING_STAGE_DIR=str(Path(directory) / ".staging")):
            signerd.reserve_issuer_prevouts(
                state, owner_id, "c1-reservation", ALLOCATION_ID, None,
                unsigned)
            active = state["owners"][owner_id]["active"]
            active["signing_state"] = "SIGNING"
            prepared, signed = signerd._signing_stage_paths(
                active["staging_id"])
            Path(prepared).write_text("prepared"); Path(prepared).chmod(0o600)
            Path(signed).write_text("signed"); Path(signed).chmod(0o600)
            state["terminal_observations"][ALLOCATION_ID] = {
                "tip": 100, "tip_hash": "10" * 32}

            class Rpc:
                def call(self, method, params=None):
                    if method == "getbtcveldsupply":
                        return {"supply_sats": 0, "tip": 200,
                                "tip_hash": "20" * 32}
                    if method == "getbtcveldc1reservation":
                        return {"allocation_id": ALLOCATION_ID,
                                "retired": True, "tip": 200}
                    if method == "getblockhash":
                        return "10" * 32
                    raise AssertionError(method)

            real_save = signerd.save_prevout_journal
            calls = 0

            def fail_removal_save(actual):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("checkpoint down")
                return real_save(actual)

            with mock.patch.object(signerd, "save_prevout_journal",
                                   side_effect=fail_removal_save):
                with self.assertRaisesRegex(RuntimeError, "checkpoint down"):
                    signerd.maintain_prevout_journal(Rpc(), state)
            self.assertTrue(Path(prepared).exists())
            self.assertTrue(Path(signed).exists())
            durable = json.loads(Path(signerd.PREVOUT_STATEF).read_text())
            self.assertIn(owner_id, durable["owners"])

    def test_unconfirmed_signed_stage_survives_partial_primary_restore(self):
        unsigned = unsigned_proposal("98" * 32)
        owner_id = signerd.c1_prevout_owner_id(ALLOCATION_ID, "RESERVE")
        state = signerd._empty_prevout_journal()
        with tempfile.TemporaryDirectory(prefix="stage-restore-") as directory, \
                mock.patch.multiple(
                    signerd,
                    PREVOUT_STATEF=str(Path(directory) / "leases.json"),
                    SIGNING_STAGE_DIR=str(Path(directory) / ".staging")):
            signerd.reserve_issuer_prevouts(
                state, owner_id, "c1-reservation", ALLOCATION_ID, None,
                unsigned)
            active = state["owners"][owner_id]["active"]
            active["signing_state"] = "SIGNED"
            active["txid"] = "aa" * 32
            signerd.save_prevout_journal(state)
            Path(signerd.SIGNING_STAGE_DIR).mkdir(mode=0o700)
            prepared, signed = signerd._signing_stage_paths(
                active["staging_id"])
            Path(prepared).write_text("prepared"); Path(prepared).chmod(0o600)
            Path(signed).write_text("signed"); Path(signed).chmod(0o600)

            self.assertEqual(
                signerd._cleanup_reconciled_signed_stages(state, set()), 0)
            self.assertTrue(Path(prepared).exists())
            self.assertTrue(Path(signed).exists())
            self.assertEqual(signerd._cleanup_reconciled_signed_stages(
                state, {active["staging_id"]}), 1)
            self.assertFalse(Path(prepared).exists())
            self.assertFalse(Path(signed).exists())

    def test_v3_revocation_promotes_full_candidate_inputs_before_ack(self):
        unsigned = unsigned_proposal("99" * 32)
        unsigned_hash = hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
        owner_id = signerd.mint_prevout_owner_id(ALLOCATION_ID)
        state = signerd._empty_prevout_journal()
        state["owners"][owner_id] = {
            "capability": "mint", "allocation_id": ALLOCATION_ID,
            "deposit_outpoint": OUTPOINT, "active": None,
            "revoked_unsigned_sha256": [unsigned_hash],
            "revoked_conflicting_input_outpoints": {unsigned_hash: []},
        }
        with mock.patch.object(signerd, "save_prevout_journal") as save:
            with self.assertRaises(signerd.UnsignedCarrierAbandoned) as caught:
                signerd.reject_conflicting_issuer_prevouts(
                    state, owner_id, "mint", ALLOCATION_ID, OUTPOINT,
                    unsigned)
        self.assertEqual(caught.exception.answer[
            "conflicting_input_outpoints"], ["99" * 32 + ":0"])
        save.assert_called_once_with(state)


class SignerAuthorityInitializationTests(unittest.TestCase):
    def test_one_shot_complete_init_and_partial_delete_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="signer-authority-init-") as directory:
            root = Path(directory)
            paths = {
                "STATEF": str(root / "signer-state.json"),
                "C1_STATEF": str(root / "c1-reservation-signer-state.json"),
                "PREVOUT_STATEF": str(root / "issuer-prevout-leases.json"),
                "SIGNER_CONFIG": str(root / "signer-config.json"),
            }
            marker = root / "signer-authority-state.json"
            Path(paths["SIGNER_CONFIG"]).write_text(json.dumps({
                "authority_state_activation_marker": str(marker),
            }))
            Path(paths["SIGNER_CONFIG"]).chmod(0o600)
            with mock.patch.multiple(
                    signerd, HERE=str(root),
                    SIGNING_STAGE_DIR=str(root / ".signing-staging"), **paths), \
                    mock.patch.object(signerd, "issuer_addr",
                                      return_value=ISSUER), \
                    mock.patch.object(signerd, "issuer_p2pkh_from_address",
                                      return_value="00" * 25):
                document = signerd.initialize_signer_authority_state()
                self.assertEqual(document,
                                 signerd._authority_state_marker_document())
                self.assertEqual(signerd.load_signer_state(), {"signed": []})
                self.assertEqual(signerd.load_c1_signer_state(),
                                 signerd._empty_c1_signer_state())
                self.assertEqual(signerd.load_prevout_journal(),
                                 signerd._empty_prevout_journal())
                cfg = signerd.load_signer_configuration()
                self.assertTrue(signerd.require_signer_authority_state_set(cfg))
                for path in (*paths.values(), str(marker)):
                    self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
                self.assertEqual(signerd.initialize_signer_authority_state(),
                                 document)

                Path(paths["C1_STATEF"]).unlink()
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    signerd.require_signer_authority_state_set(cfg)
                with self.assertRaises(FileNotFoundError):
                    signerd.load_c1_signer_state()
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    signerd.initialize_signer_authority_state()

    def test_activated_set_reparses_every_member_and_reconciles(self):
        corruptions = {
            "STATEF": '[]\n',
            "C1_STATEF": '{}\n',
            "PREVOUT_STATEF": '{}\n',
        }
        for member, malformed in corruptions.items():
            with self.subTest(member=member), tempfile.TemporaryDirectory(
                    prefix="signer-authority-revalidate-") as directory:
                root = Path(directory)
                marker = root / "signer-authority-state.json"
                paths = {
                    "STATEF": str(root / "signer-state.json"),
                    "C1_STATEF": str(root / "c1-reservation-signer-state.json"),
                    "PREVOUT_STATEF": str(root / "issuer-prevout-leases.json"),
                    "SIGNER_CONFIG": str(root / "signer-config.json"),
                }
                Path(paths["SIGNER_CONFIG"]).write_text(json.dumps({
                    "authority_state_activation_marker": str(marker),
                }))
                Path(paths["SIGNER_CONFIG"]).chmod(0o600)
                with mock.patch.multiple(
                        signerd, HERE=str(root),
                        SIGNING_STAGE_DIR=str(root / ".signing-staging"),
                        **paths), \
                        mock.patch.object(signerd, "issuer_addr",
                                          return_value=ISSUER), \
                        mock.patch.object(
                            signerd, "issuer_p2pkh_from_address",
                            return_value="00" * 25):
                    signerd.initialize_signer_authority_state()
                    Path(paths[member]).write_text(malformed)
                    Path(paths[member]).chmod(0o600)
                    with self.assertRaises(ValueError):
                        signerd.initialize_signer_authority_state()

        with tempfile.TemporaryDirectory(
                prefix="signer-authority-reconcile-") as directory:
            root = Path(directory)
            marker = root / "signer-authority-state.json"
            paths = {
                "STATEF": str(root / "signer-state.json"),
                "C1_STATEF": str(root / "c1-reservation-signer-state.json"),
                "PREVOUT_STATEF": str(root / "issuer-prevout-leases.json"),
                "SIGNER_CONFIG": str(root / "signer-config.json"),
            }
            Path(paths["SIGNER_CONFIG"]).write_text(json.dumps({
                "authority_state_activation_marker": str(marker),
            }))
            Path(paths["SIGNER_CONFIG"]).chmod(0o600)
            with mock.patch.multiple(
                    signerd, HERE=str(root),
                    SIGNING_STAGE_DIR=str(root / ".signing-staging"), **paths), \
                    mock.patch.object(signerd, "issuer_addr",
                                      return_value=ISSUER), \
                    mock.patch.object(signerd, "issuer_p2pkh_from_address",
                                      return_value="00" * 25):
                signerd.initialize_signer_authority_state()
                with mock.patch.object(
                        signerd, "load_or_reconcile_prevout_journal",
                        side_effect=ValueError("cross-state mismatch")):
                    with self.assertRaisesRegex(ValueError,
                                                "cross-state mismatch"):
                        signerd.initialize_signer_authority_state()

    def test_complete_pre_marker_upgrade_is_adopted_without_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="signer-authority-adopt-") as directory:
            root = Path(directory)
            marker = root / "signer-authority-state.json"
            paths = {
                "STATEF": str(root / "signer-state.json"),
                "C1_STATEF": str(root / "c1-reservation-signer-state.json"),
                "PREVOUT_STATEF": str(root / "issuer-prevout-leases.json"),
                "SIGNER_CONFIG": str(root / "signer-config.json"),
            }
            Path(paths["SIGNER_CONFIG"]).write_text(json.dumps({
                "authority_state_activation_marker": str(marker),
            }))
            Path(paths["SIGNER_CONFIG"]).chmod(0o600)
            with mock.patch.multiple(signerd, HERE=str(root), **paths), \
                    mock.patch.object(signerd, "issuer_addr",
                                      return_value=ISSUER), \
                    mock.patch.object(signerd, "issuer_p2pkh_from_address",
                                      return_value="00" * 25):
                signerd.save_signer_state_durable({"signed": []})
                signerd.save_c1_signer_state(signerd._empty_c1_signer_state())
                signerd.save_prevout_journal(signerd._empty_prevout_journal())
                before = {
                    path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    for path in (paths["STATEF"], paths["C1_STATEF"],
                                 paths["PREVOUT_STATEF"])}
                signerd.initialize_signer_authority_state()
                after = {
                    path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    for path in before}
                self.assertEqual(after, before)
                self.assertTrue(marker.exists())

    def test_pre_marker_partial_upgrade_set_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="signer-authority-partial-") as directory:
            root = Path(directory)
            marker = root / "signer-authority-state.json"
            config = root / "signer-config.json"
            config.write_text(json.dumps({
                "authority_state_activation_marker": str(marker),
            }))
            config.chmod(0o600)
            with mock.patch.multiple(
                    signerd, HERE=str(root),
                    STATEF=str(root / "signer-state.json"),
                    C1_STATEF=str(root / "c1-reservation-signer-state.json"),
                    PREVOUT_STATEF=str(root / "issuer-prevout-leases.json"),
                    SIGNER_CONFIG=str(config)):
                signerd.save_signer_state_durable({"signed": []})
                with self.assertRaisesRegex(ValueError, "partial"):
                    signerd.initialize_signer_authority_state()
                self.assertFalse(marker.exists())

    def test_missing_prevout_member_is_never_reconstructed_from_other_caches(self):
        with tempfile.TemporaryDirectory(prefix="missing-prevout-") as directory, \
                mock.patch.multiple(
                    signerd,
                    PREVOUT_STATEF=str(Path(directory) / "missing.json"),
                    SIGNING_STAGE_DIR=str(Path(directory) / ".staging")):
            with self.assertRaisesRegex(FileNotFoundError, "partial"):
                signerd.load_or_reconcile_prevout_journal(
                    {}, ISSUER, "00" * 25)


class GlobalCoordinatorMaintenanceTests(unittest.TestCase):
    @staticmethod
    def record():
        return {"kind": "active", "allocation_sha256": "44" * 32,
                "request_id": REQUEST_ID, "terminal_observed_tip": 1,
                "RESERVE": None, "EXPOSE": None, "CANCEL": None, "FUND": []}

    def test_fair_reaper_compacts_every_terminal_without_client_retry(self):
        ids = ["%032x" % value for value in range(1, 6)]
        state = {"version": 4, "sequence": 1,
                 "records": {key: self.record() for key in ids},
                 "compaction_cursor": None}

        class Rpc:
            def call(self, method, params=None):
                self.last = params[0]
                return {"allocation_id": params[0], "retired": True,
                        "tip": 500}

        visited = []

        def compact(_rpc, _cfg, actual, allocation_id, _record, _status,
                    allow_archive=True):
            visited.append(allocation_id)
            if allow_archive:
                del actual["records"][allocation_id]
                return True
            return False

        with mock.patch.object(reservationd, "persist"), \
                mock.patch.object(reservationd, "compact_terminal",
                                  side_effect=compact):
            while state["records"]:
                reservationd.maintain_terminal_records(
                    Rpc(), {}, state, scan_limit=2, archive_limit=2)
        self.assertEqual(set(visited), set(ids))
        self.assertEqual(state["records"], {})


if __name__ == "__main__":
    unittest.main()
