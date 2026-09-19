#!/usr/bin/env python3
"""Adversarial tests for independent issuer-wrap authorization."""
import copy
import hashlib
import json
import shutil
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock
import subprocess

import veld_peg_solvency as sol
import veld_wt_reserve as witness


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
ISSUER = "V" + "1" * 33
RECIPIENT = "V" + "2" * 33
TIP_HASH = "33" * 32
BTC_TXID = "44" * 32
OUTPOINT = BTC_TXID + ":0"
REAL_FALSE = str(Path("/bin/false").resolve())
_EXECUTABLE_FIXTURE = None


def setUpModule():
    global _EXECUTABLE_FIXTURE, REAL_FALSE
    _EXECUTABLE_FIXTURE = tempfile.TemporaryDirectory(prefix="witness-executable-")
    target = Path(_EXECUTABLE_FIXTURE.name) / "false"
    shutil.copyfile(Path("/bin/false").resolve(), target)
    target.chmod(0o700)
    REAL_FALSE = str(target)


def tearDownModule():
    if _EXECUTABLE_FIXTURE is not None:
        _EXECUTABLE_FIXTURE.cleanup()


def bech32m_address(script):
    program = bytes.fromhex(script[4:])
    data = [1]
    accumulator = bits = 0
    for byte in program:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((accumulator >> bits) & 31)
    if bits:
        data.append((accumulator << (5 - bits)) & 31)
    values = ([ord(char) >> 5 for char in "bc"] + [0] +
              [ord(char) & 31 for char in "bc"] + data + [0] * 6)
    checksum = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
                  0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    checksum ^= 0x2BC830A3
    tail = [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
    return "bc1" + "".join(BECH32[value] for value in data + tail)


def unsigned_tx(tag=1):
    return (b"\x01\x00\x00\x00" + b"\x01" + bytes([tag]) * 32 +
            b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff" +
            b"\x01" + (1000).to_bytes(8, "little") + b"\x02\x6a\x00" +
            b"\x00\x00\x00\x00").hex()


class FakeVeldRpc:
    def __init__(self, allocation_id="%032x" % 1, recipient=RECIPIENT,
                 sats=62_500, script=None, blind="22" * 32,
                 tip=10, tip_hash=TIP_HASH, supply_sats=0):
        self.allocation_id = allocation_id
        self.recipient = recipient
        self.sats = sats
        self.script = script or ("5120" + "11" * 32)
        self.blind = blind
        self.tip = tip
        self.tip_hash = tip_hash
        self.supply_sats = supply_sats

    def call(self, method, params=None):
        if method == "getrawtransaction":
            raise RuntimeError("not yet canonical")
        if method == "getblockhash":
            return self.tip_hash
        if method == "getbtcveldsupply":
            return {"supply_sats": self.supply_sats, "tip": self.tip,
                    "tip_hash": self.tip_hash}
        if method == "getbtcveldc1reservation":
            return {
                "allocation_id": self.allocation_id,
                "found": True, "active": True, "retired": False,
                "sequence": int(self.allocation_id, 16),
                "last_sequence": int(self.allocation_id, 16),
                "exposed": True,
                "exposure_canonical_depth_reached": True,
                "exposure_confirmations": 101,
                "required_confirmations": 101,
                "canonical_depth_reached": True,
                "funded": True, "funding_outpoint": OUTPOINT,
                "funding_confirmations": 1,
                "funding_canonical_depth_reached": False,
                "recipient": self.recipient, "amount_sats": self.sats,
                "allocation_commitment": witness.allocation_commitment(
                    self.allocation_id, self.recipient, self.sats,
                    self.script, self.blind),
                "tip": self.tip,
            }
        if method == "getbtcveldmintstatus":
            return {
                "outpoint": OUTPOINT, "consumed": True, "minted": False,
                "proof_version": "MNP1", "accepted_effect_kind": "C1_FUND",
                "proof_hex": "00" * 32, "root": "55" * 32, "count": 1,
                "c1_allocation_id": self.allocation_id,
                "accepted_txid": "77" * 32,
                "accepted_block_height": self.tip,
                "accepted_block_hash": self.tip_hash,
                "accepted_tx_index": 0, "accepted_marker_vout": 0,
                "consumer_txid": "77" * 32,
                "consumer_block_height": self.tip,
                "consumer_block_hash": self.tip_hash,
                "consumer_tx_index": 0, "consumer_marker_vout": 0,
                "credit_txid": None, "credit_block_height": None,
                "credit_block_hash": None, "credit_tx_index": None,
                "credit_marker_vout": None,
                "tip": self.tip, "tip_hash": self.tip_hash,
            }
        raise AssertionError(method)


class FakePolicyRpc:
    def __init__(self, compiled_k=6, best_height=899_000, mint_live=True,
                 completion_live=True):
        self.compiled_k = compiled_k
        self.best_height = best_height
        self.mint_live = mint_live
        self.completion_live = completion_live

    def call(self, method, params=None):
        if method == "getpeginfo":
            return {"active": True, "spv_active": True, "token_id": "btcVELD",
                    "spv_k_btc": self.compiled_k,
                    "peg_unlocked": True, "mint_live": self.mint_live,
                    "completion_live": self.completion_live}
        if method == "getbtcheaderinfo":
            return {"spv_active": True, "best_height": self.best_height,
                    "k_btc": self.compiled_k}
        raise AssertionError(method)


class FakePublicPolicyRpc:
    def call(self, method, params=None):
        if method == "getpeginfo":
            return {
                "peg_unlocked": True, "mint_live": True,
                "issuer_max_per_mint_sats": 1_000_000_000,
                "issuer_static_custody_cap_sats": 1_000_000_000,
                "issuer_effective_custody_cap_sats": 100_000,
                "issuer_mint_headroom_sats": 100_000,
                "issuer_reserved_sats": 0,
                "supply_sats": 0,
                "tip": 100,
            }
        if method == "getbtcveldsupply":
            return {"supply_sats": 0, "tip": 100,
                    "tip_hash": "55" * 32}
        if method == "getblockhash":
            return "55" * 32
        raise AssertionError(method)


class FakeBitcoin:
    def __init__(self, script, sats=62_500, confirmations=6):
        self.script = script
        self.sats = sats
        self.confirmations = confirmations
        self.tip_age_alert_secs = 3600
        self.max_tip_age_secs = 7200
        self.before = TIP_HASH
        self.after = TIP_HASH
        self.hash_reads = 0
        self.ibd = False
        self.blocks = 900_000
        self.headers = 900_000
        self.header_time = int(time.time())

    def call(self, method, *args):
        if method == "getbestblockhash":
            self.hash_reads += 1
            return self.before if self.hash_reads % 2 else self.after
        if method == "getblockchaininfo":
            return {"chain": "main", "initialblockdownload": self.ibd,
                    "blocks": self.blocks, "headers": self.headers,
                    "bestblockhash": self.before}
        if method == "getblockheader":
            return {"hash": self.before, "time": self.header_time}
        if method == "gettxout":
            if args[:2] != (BTC_TXID, 0):
                return None
            return {
                "confirmations": self.confirmations,
                "value": Decimal(self.sats) / Decimal(100_000_000),
                "scriptPubKey": {"hex": self.script},
            }
        raise AssertionError(method)


class WrapAllocationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wrap-witness-")
        self.state = Path(self.temp.name) / "state"
        self.state.mkdir(mode=0o700)
        self.policy = dict(witness.C1_POLICY_EXACT)
        self.policy.update({
            "record_sequence": 1,
            "previous_policy_sha256": "0" * 64,
            "public_descriptor_range": [1000, 10999],
            "archive_authority_id": "c4-test-authority",
        })
        self.policy_hash = "99" * 32
        scripts = tuple("5120%064x" % (index + 1) for index in range(11000))
        self.binding = {"range": [0, 10999], "script_pubkeys": scripts}
        self.script = scripts[1000]
        self.address = bech32m_address(self.script)
        self.cfg = {
            "production": True,
            "issuer_id": ISSUER,
            "witness_id": "witness-1",
            "issuer_p2pkh_hex": "76a914" + "11" * 20 + "88ac",
            "state_dir": str(self.state),
            "wrap_allocation_authority": {
                "version": 2,
                "initial_descriptor_index": 1000,
                "allow_initial_ledger_creation": False,
                "checkpoint_command": [REAL_FALSE],
            },
            "reservation_ledger": {
                "max_active_rows": 10_000,
                "max_active_bytes": 256 * 1024 * 1024,
                "max_terminal_rows": 999,
                "max_terminal_bytes": 4 * 1024 * 1024,
                "min_free_bytes": 16 * 1024 * 1024,
                "terminal_archive_command": [REAL_FALSE],
            },
        }
        self.paths = witness._paths(self.cfg)
        witness.atomic_write(
            self.paths["ledger"], json.dumps(
                witness._empty_ledger(), sort_keys=True,
                separators=(",", ":")) + "\n")
        witness.atomic_write(
            self.paths["terminal"], witness._empty_terminal_log_text())
        empty = witness._empty_allocation_ledger(
            self.cfg, self.policy, self.policy_hash)
        witness.atomic_write(
            self.paths["allocations"],
            json.dumps(empty, sort_keys=True, separators=(",", ":")) + "\n")
        self.now = int(time.time())
        self.allocation = {
            "request_id": "aa" * 16,
            "principal_hash": "bb" * 32,
            "veld_address": RECIPIENT,
            "amount_sats": 62_500,
            "descriptor_index": 1000,
            "btc_address": self.address,
            "script_pubkey": self.script,
            "admitted_at": self.now - 60,
            "expires_at": self.now - 60 + 604_800,
            "commitment_blind": "22" * 32,
            "consensus_allocation_id": "%032x" % 1,
        }
        self.checkpoint_patch = mock.patch.object(
            witness, "_checkpoint_allocation_ledger")
        self.checkpoint_patch.start()

    def tearDown(self):
        self.checkpoint_patch.stop()
        self.temp.cleanup()

    def register(self, allocation=None):
        ledger = witness._load_allocation_ledger(
            self.paths["allocations"], self.cfg, self.binding,
            self.policy, self.policy_hash)
        return witness.handle_register_allocation({
            "version": 4,
            "action": "register_allocation",
            "capacity_policy_sha256": self.policy_hash,
            "allocation": copy.deepcopy(allocation or self.allocation),
        }, self.cfg, self.paths, ledger, self.binding,
            self.policy, self.policy_hash,
            issuer_headroom_sats=100_000_000,
            issuer_reserved_sats=0)

    def test_c1_public_allocation_reaches_final_deposit_validation(self):
        """The production index-1000 schema must not fall into legacy checks."""
        now = int(time.time())
        policy = dict(witness.C1_POLICY_EXACT)
        policy.update({
            "record_sequence": 1,
            "previous_policy_sha256": "0" * 64,
            "public_descriptor_range": [1000, 10999],
            "archive_authority_id": "c4-test-authority",
        })
        scripts = tuple(
            "5120%064x" % (index + 1) for index in range(11000))
        script = scripts[1000]
        address = bech32m_address(script)
        record = {
            "request_id": "ca" * 16,
            "principal_hash": "cb" * 32,
            "veld_address": RECIPIENT,
            "amount_sats": 100_000,
            "descriptor_index": 1000,
            "btc_address": address,
            "script_pubkey": script,
            "admitted_at": now - 60,
            "expires_at": now - 60 + 604_800,
            "registered_at": now - 30,
            "deposit_observed_at": None,
            "funded_reserved_at": None,
            "funding_outpoint": None,
            "minted_at": None,
            "commitment_blind": "ab" * 32,
            "consensus_allocation_id": "%032x" % 1,
        }
        claim = {
            "request_id": record["request_id"],
            "btc_address": address,
            "script_pubkey": script,
            "deposit_outpoint": OUTPOINT,
            "descriptor_index": 1000,
            "capacity_policy_sha256": "aa" * 32,
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
            "consensus_allocation_id": record["consensus_allocation_id"],
            "commitment_blind": record["commitment_blind"],
        }
        bitcoin = FakeBitcoin(script, sats=100_000, confirmations=6)
        result = witness._verify_allocation_deposit(
            claim, RECIPIENT, 100_000, OUTPOINT,
            {"allocations": [record]}, bitcoin,
            {"range": [0, 10999], "script_pubkeys": scripts},
            899_999, now=now, c1_policy=policy,
            allocation_policy_sha256="aa" * 32)
        self.assertIs(result, record)

        for field, value in (
                ("descriptor_index", 999),
                ("capacity_policy_sha256", "bb" * 32),
                ("public_descriptor_range_start", 999),
                ("public_descriptor_range_end", 11000)):
            with self.subTest(field=field):
                tampered = dict(claim); tampered[field] = value
                with self.assertRaises(SystemExit):
                    witness._verify_allocation_deposit(
                        tampered, RECIPIENT, 100_000, OUTPOINT,
                        {"allocations": [record]}, bitcoin,
                        {"range": [0, 10999], "script_pubkeys": scripts},
                        899_999, now=now, c1_policy=policy,
                        allocation_policy_sha256="aa" * 32)

        # A retry under the immediately linked range-only successor refreshes
        # the one active receipt in place; it never reserves headroom twice.
        funded = dict(record)
        funded["deposit_observed_at"] = now - 2
        funded["funded_reserved_at"] = now - 1
        funded["funding_outpoint"] = OUTPOINT
        raw = unsigned_tx(7)
        digest = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        request = {
            "action": "reserve", "issuer_id": ISSUER,
            "request_id": digest, "unsigned_tx_sha256": digest,
            "unsigned_tx_hex": raw, "sats": 100_000,
            "recipient": RECIPIENT, "allocation": dict(claim),
            "beat_seq": 1, "tip": 10, "tip_hash": TIP_HASH,
        }
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            1_000_000, 0, 0, 10, TIP_HASH, 1, 120), now)
        ledger = witness._empty_ledger()
        decoded = subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "from": ISSUER, "to": RECIPIENT, "sats": 100_000,
            "memo": "MNP2;%s;%s;%s;%s" % (
                record["consensus_allocation_id"], script,
                record["commitment_blind"], OUTPOINT),
        }), stderr="")
        funded_rpc = FakeVeldRpc(
            allocation_id=record["consensus_allocation_id"],
            recipient=RECIPIENT, sats=100_000, script=script,
            blind=record["commitment_blind"], supply_sats=0)
        with mock.patch.object(witness, "_sign_receipt",
                               side_effect=lambda core, cfg: {
                                   **core, "sig_alg": "mldsa65", "sig": "00"}), \
             mock.patch.object(witness.subprocess, "run", return_value=decoded):
            first = witness.handle_reserve(
                request, self.cfg, self.paths, ledger, beat, funded_rpc,
                {"allocations": [funded]}, bitcoin,
                {"range": [0, 10999], "script_pubkeys": scripts}, 899_999,
                policy, "aa" * 32)
            reservation_id = first["receipt"]["reservation_id"]
            raised = dict(policy)
            raised.update({
                "record_sequence": 2,
                "previous_policy_sha256": "aa" * 32,
                "public_descriptor_range": [1000, 11000],
            })
            raised_claim = dict(claim)
            raised_claim["capacity_policy_sha256"] = "bb" * 32
            raised_claim["public_descriptor_range_end"] = 11000
            request["allocation"] = raised_claim
            raised_scripts = scripts + ("5120" + "ff" * 32,)
            second = witness.handle_reserve(
                request, self.cfg, self.paths, ledger, beat, funded_rpc,
                {"allocations": [funded]}, bitcoin,
                {"range": [0, 11000], "script_pubkeys": raised_scripts},
                899_999, raised, "bb" * 32)
        self.assertTrue(second["idempotent"])
        self.assertEqual(len(ledger["reservations"]), 1)
        self.assertEqual(second["receipt"]["reservation_id"], reservation_id)
        self.assertEqual(second["receipt"][
            "allocation_capacity_policy_sha256"], "bb" * 32)

        # A response-losing register retry is not a blind acknowledgement: the
        # complete existing liability must still fit the newly reconciled
        # issuer headroom.
        authority = {
            "version": witness.ALLOCATION_LEDGER_VERSION,
            "initial_descriptor_index": 1000,
            "capacity_policy_sha256": "aa" * 32,
            "capacity_policy_sequence": 1,
            "public_descriptor_range_end": 10999,
            "last_consensus_sequence": 1,
            "allocations": [funded], "events": [],
        }
        authority["events"] = [
            {"action": "registered", "at": record["registered_at"],
             "request_id": record["request_id"]},
            {"action": "deposit_observed",
             "at": funded["deposit_observed_at"],
             "request_id": record["request_id"]},
            {"action": "funded_reservation_observed",
             "at": funded["funded_reserved_at"],
             "request_id": record["request_id"]},
        ]
        register_req = {
            "version": 4, "action": "register_allocation",
            "capacity_policy_sha256": "aa" * 32,
            "allocation": {key: record[key]
                           for key in witness.ALLOCATION_FIELDS},
        }
        with self.assertRaises(SystemExit):
            witness.handle_register_allocation(
                register_req, self.cfg, self.paths, authority,
                {"range": [0, 10999], "script_pubkeys": scripts},
                policy, "aa" * 32, now=now,
                issuer_headroom_sats=99_999,
                issuer_reserved_sats=0)
        retry = witness.handle_register_allocation(
            register_req, self.cfg, self.paths, authority,
            {"range": [0, 10999], "script_pubkeys": scripts},
            policy, "aa" * 32, now=now,
            issuer_headroom_sats=100_000,
            issuer_reserved_sats=0)
        self.assertTrue(retry["idempotent"])
        self.assertEqual(retry["funded_reserved_at"],
                         funded["funded_reserved_at"])

    def registered_ledger(self):
        return witness._load_allocation_ledger(
            self.paths["allocations"], self.cfg, self.binding,
            self.policy, self.policy_hash)

    def claim(self):
        return {
            "request_id": self.allocation["request_id"],
            "btc_address": self.address,
            "script_pubkey": self.script,
            "deposit_outpoint": OUTPOINT,
            "descriptor_index": self.allocation["descriptor_index"],
            "capacity_policy_sha256": self.policy_hash,
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
            "consensus_allocation_id":
                self.allocation["consensus_allocation_id"],
            "commitment_blind": self.allocation["commitment_blind"],
        }

    def request(self, tag=1):
        raw = unsigned_tx(tag)
        digest = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        return {
            "action": "reserve", "issuer_id": ISSUER,
            "request_id": digest, "unsigned_tx_sha256": digest,
            "unsigned_tx_hex": raw, "sats": 62_500,
            "recipient": RECIPIENT, "allocation": self.claim(),
            "beat_seq": 1, "tip": 10, "tip_hash": TIP_HASH,
        }

    def decoded(self, recipient=RECIPIENT, sats=62_500,
                outpoint=OUTPOINT):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "from": ISSUER, "to": recipient, "sats": sats,
            "memo": "MNP2;%s;%s;%s;%s" % (
                self.allocation["consensus_allocation_id"], self.script,
                self.allocation["commitment_blind"], outpoint),
        }), stderr="")

    def test_forced_reservation_entrypoint_is_unconditionally_production_only(self):
        witness._require_production_reservation_service({"production": True})
        for cfg in ({}, {"production": False}, {"production": 1},
                    {"production": "true"}, None):
            with self.subTest(cfg=cfg), self.assertRaises(SystemExit):
                witness._require_production_reservation_service(cfg)

        relative = copy.deepcopy(self.cfg)
        relative["reservation_ledger"]["terminal_archive_command"] = ["archive-hook"]
        with self.assertRaises(SystemExit):
            witness._reservation_ledger_policy(relative, production=True)

        source = Path(witness.__file__).read_text(encoding="utf-8")
        main_at = source.index("def main():")
        gate_at = source.index("_require_production_reservation_service(cfg)",
                               main_at)
        ledger_at = source.index("ledger = _load_ledger", main_at)
        self.assertLess(gate_at, ledger_at)
        self.assertNotIn('if cfg.get("production") is True:',
                         source[source.index('elif req.get("action") == "reserve":',
                                             main_at):ledger_at + 2500])

    def test_missing_reservation_ledger_and_armed_live_allocator_fail_closed(self):
        missing = str(self.state / "missing-mint-reservations.json")
        with self.assertRaises(SystemExit):
            witness._load_ledger(missing)

        disarmed = copy.deepcopy(self.cfg["wrap_allocation_authority"])
        witness._require_allocation_service_mode(disarmed, initialize=False)
        with self.assertRaises(SystemExit):
            witness._require_allocation_service_mode(disarmed, initialize=True)

        armed = dict(disarmed, allow_initial_ledger_creation=True)
        witness._require_allocation_service_mode(armed, initialize=True)
        with self.assertRaises(SystemExit):
            witness._require_allocation_service_mode(armed, initialize=False)

    def test_forced_command_rechecks_compiled_confirmation_and_spv_policy(self):
        with mock.patch.object(witness.custody_binding, "verify_peg_identity"):
            self.assertEqual(witness._verify_forced_command_peg_policy(
                FakePolicyRpc(), {"btc": {"confirmations": 6}}, self.binding),
                899_000)
            self.assertEqual(witness._verify_forced_command_peg_policy(
                FakePolicyRpc(mint_live=False, completion_live=True),
                {"btc": {"confirmations": 6}}, self.binding), 899_000)
            for rpc, cfg in (
                    (FakePolicyRpc(compiled_k=7), {"btc": {"confirmations": 6}}),
                    (FakePolicyRpc(best_height=0), {"btc": {"confirmations": 6}}),
                    (FakePolicyRpc(completion_live=False),
                     {"btc": {"confirmations": 6}}),
                    (FakePolicyRpc(), {"btc": {"confirmations": 5}}),
                    (FakePolicyRpc(), {"btc": {"confirmations": True}})):
                with self.subTest(rpc=rpc.__dict__, cfg=cfg), \
                     self.assertRaises(SystemExit):
                    witness._verify_forced_command_peg_policy(
                        rpc, cfg, self.binding)

    def test_production_bitcoin_policy_is_exact_not_operator_tunable(self):
        good = {
            "cli_base": ["bitcoin-cli"], "wallet": "custody-watch",
            "confirmations": 6, "tip_age_alert_secs": 3600,
            "max_tip_age_secs": 7200,
        }
        btc = witness.BitcoinCli(good)
        self.assertEqual(
            (btc.tip_age_alert_secs, btc.max_tip_age_secs), (3600, 7200))
        for field, value in (("tip_age_alert_secs", 3599),
                             ("tip_age_alert_secs", 3601),
                             ("max_tip_age_secs", 7199),
                             ("max_tip_age_secs", 7201)):
            with self.subTest(field=field, value=value):
                bad = dict(good); bad[field] = value
                with self.assertRaisesRegex(ValueError, "btc policy"):
                    witness.BitcoinCli(bad)

    def test_c5_five_point_boundaries_cover_allocation_and_mint_reserve(self):
        self.register()
        allocations = self.registered_ledger()
        expected = {
            3_599: "FRESH", 3_600: "ALERT", 7_199: "ALERT",
            7_200: "RECOVERY_ONLY", 7_201: "RECOVERY_ONLY",
        }
        for age, phase in expected.items():
            with self.subTest(path="mint-reserve", age=age):
                btc = FakeBitcoin(self.script)
                btc.header_time = 100_000 - age
                if phase == "RECOVERY_ONLY":
                    with self.assertRaises(SystemExit):
                        witness._verify_allocation_deposit(
                            self.claim(), RECIPIENT, 62_500, OUTPOINT,
                            allocations, btc, self.binding, 899_000,
                            now=100_000, c1_policy=self.policy,
                            allocation_policy_sha256=self.policy_hash)
                else:
                    self.assertIs(
                        witness._verify_allocation_deposit(
                            self.claim(), RECIPIENT, 62_500, OUTPOINT,
                            allocations, btc, self.binding, 899_000,
                            now=100_000, c1_policy=self.policy,
                            allocation_policy_sha256=self.policy_hash),
                        allocations["allocations"][0])

            with self.subTest(path="public-allocation", age=age):
                btc = FakeBitcoin(self.script)
                btc.header_time = 100_000 - age
                cfg = {
                    "veld_rpc": {"url": "http://127.0.0.1"},
                    "btc": {
                        "cli_base": ["bitcoin-cli"],
                        "wallet": "custody-watch", "confirmations": 6,
                        "tip_age_alert_secs": 3600,
                        "max_tip_age_secs": 7200,
                    },
                }
                with mock.patch.object(
                        witness, "VeldRpc", return_value=FakePublicPolicyRpc()), \
                     mock.patch.object(witness, "BitcoinCli", return_value=btc):
                    if phase == "RECOVERY_ONLY":
                        with self.assertRaises(SystemExit):
                            witness._verify_public_allocation_backend(
                                cfg, dict(witness.C1_POLICY_EXACT), now=100_000)
                    else:
                        result = witness._verify_public_allocation_backend(
                            cfg, dict(witness.C1_POLICY_EXACT), now=100_000)
                        self.assertEqual(result["phase"], phase)

        # A reservation durably admitted while fresh remains exactly replayable
        # in recovery-only; a first-seen reservation was refused above.
        now = int(time.time())
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            100_000, 0, 0, 10, TIP_HASH, 1, 120), now)
        ledger = witness._empty_ledger()
        request = self.request()
        fresh = FakeBitcoin(self.script)
        with mock.patch.object(witness, "_sign_receipt",
                               side_effect=lambda core, cfg: {
                                   **core, "sig_alg": "mldsa65", "sig": "00"}), \
             mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()):
            first = witness.handle_reserve(
                request, self.cfg, self.paths, ledger, beat,
                FakeVeldRpc(script=self.script), allocations, fresh,
                self.binding, 899_000, self.policy, self.policy_hash)
            recovery = FakeBitcoin(self.script)
            recovery.header_time = now - 7_200
            replay = witness.handle_reserve(
                request, self.cfg, self.paths, ledger, beat,
                FakeVeldRpc(script=self.script), allocations, recovery,
                self.binding, 899_000, self.policy, self.policy_hash)
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(first["receipt"]["reservation_id"],
                         replay["receipt"]["reservation_id"])

    def test_public_allocation_rejects_same_height_mixed_capacity_snapshot(self):
        class MovingSupplyRpc(FakePublicPolicyRpc):
            def __init__(self):
                self.supply_reads = 0

            def call(self, method, params=None):
                if method == "getbtcveldsupply":
                    self.supply_reads += 1
                    result = super().call(method, params)
                    if self.supply_reads == 2:
                        # Same reported height, different canonical block:
                        # never combine A's capacity with B's supply.
                        result["tip_hash"] = "66" * 32
                    return result
                return super().call(method, params)

        cfg = {
            "veld_rpc": {"url": "http://127.0.0.1"},
            "btc": {
                "cli_base": ["bitcoin-cli"],
                "wallet": "custody-watch", "confirmations": 6,
                "tip_age_alert_secs": 3600,
                "max_tip_age_secs": 7200,
            },
        }
        with mock.patch.object(witness, "VeldRpc",
                               return_value=MovingSupplyRpc()), \
             mock.patch.object(witness, "BitcoinCli",
                               return_value=FakeBitcoin(self.script)), \
             mock.patch.object(
                 witness, "refuse",
                 side_effect=lambda message: (_ for _ in ()).throw(
                     RuntimeError(message))):
            with self.assertRaisesRegex(
                    RuntimeError, "capacity tuple changed/is incoherent"):
                witness._verify_public_allocation_backend(
                    cfg, dict(witness.C1_POLICY_EXACT), now=100_000)

    def test_registration_is_contiguous_immutable_and_idempotent(self):
        first = self.register()
        second = self.register()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        verified = self.registered_ledger()
        answer = witness.handle_register_allocation({
            "version": 4, "action": "verify_allocation",
            "capacity_policy_sha256": self.policy_hash,
            "allocation": copy.deepcopy(self.allocation),
        }, self.cfg, self.paths, verified, self.binding,
            self.policy, self.policy_hash)
        self.assertTrue(answer["idempotent"])
        self.assertEqual(len(self.registered_ledger()["allocations"]), 1)

        conflict = dict(self.allocation)
        conflict["veld_address"] = "V" + "3" * 33
        with self.assertRaises(SystemExit):
            self.register(conflict)
        skipped = dict(self.allocation)
        skipped.update({
            "request_id": "cc" * 16,
            "descriptor_index": 1001,
            "script_pubkey": self.binding["script_pubkeys"][1001],
            "btc_address": bech32m_address(
                self.binding["script_pubkeys"][1001]),
            "commitment_blind": "33" * 32,
            "consensus_allocation_id": "%032x" % 3,
        })
        with self.assertRaises(SystemExit):
            self.register(skipped)
        absent = dict(skipped)
        absent["descriptor_index"] = 1002
        absent["script_pubkey"] = self.binding["script_pubkeys"][1002]
        absent["btc_address"] = bech32m_address(
            self.binding["script_pubkeys"][1002])
        absent["consensus_allocation_id"] = "%032x" % 2
        with self.assertRaises(SystemExit):
            witness.handle_register_allocation({
                "version": 4, "action": "verify_allocation",
                "capacity_policy_sha256": self.policy_hash,
                "allocation": absent,
            }, self.cfg, self.paths, self.registered_ledger(), self.binding,
                self.policy, self.policy_hash)

    def test_reservation_requires_registered_confirmed_exact_bitcoin_output(self):
        self.register()
        allocations = self.registered_ledger()
        btc = FakeBitcoin(self.script)
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            100_000, 0, 0, 10, TIP_HASH, 1, 120), int(time.time()))
        ledger = witness._empty_ledger()
        with mock.patch.object(witness, "_sign_receipt",
                               side_effect=lambda core, cfg: {
                                   **core, "sig_alg": "mldsa65", "sig": "00"}), \
             mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()):
            answer = witness.handle_reserve(
                self.request(), self.cfg, self.paths, ledger, beat,
                FakeVeldRpc(script=self.script), allocations, btc,
                self.binding, 899_000, self.policy, self.policy_hash)
        self.assertFalse(answer["idempotent"])
        self.assertEqual(len(ledger["reservations"]), 1)

        cases = []
        underconfirmed = FakeBitcoin(self.script, confirmations=5)
        cases.append(("underconfirmed", self.request(), underconfirmed,
                      self.decoded()))
        wrong_script = FakeBitcoin("5120" + "ff" * 32)
        cases.append(("script", self.request(), wrong_script, self.decoded()))
        wrong_amount = FakeBitcoin(self.script, sats=62_501)
        cases.append(("amount", self.request(), wrong_amount, self.decoded()))
        reorg = FakeBitcoin(self.script); reorg.after = "55" * 32
        cases.append(("tip-race", self.request(), reorg, self.decoded()))
        ibd = FakeBitcoin(self.script); ibd.ibd = True
        cases.append(("ibd", self.request(), ibd, self.decoded()))
        header_lag = FakeBitcoin(self.script); header_lag.headers += 1
        cases.append(("header-lag", self.request(), header_lag, self.decoded()))
        stale = FakeBitcoin(self.script)
        stale.header_time -= stale.max_tip_age_secs + 1
        cases.append(("stale-tip", self.request(), stale, self.decoded()))
        behind_spv = FakeBitcoin(self.script); behind_spv.blocks = 898_999
        behind_spv.headers = 898_999
        cases.append(("behind-veld-spv", self.request(), behind_spv,
                      self.decoded()))
        wrong_recipient = self.request()
        wrong_recipient["recipient"] = "V" + "4" * 33
        cases.append(("recipient", wrong_recipient, FakeBitcoin(self.script),
                      self.decoded(recipient=wrong_recipient["recipient"])))
        for label, request, candidate_btc, decoded in cases:
            with self.subTest(label=label), \
                 mock.patch.object(witness.subprocess, "run",
                                   return_value=decoded):
                with self.assertRaises(SystemExit):
                    witness.handle_reserve(
                        request, self.cfg, self.paths,
                        witness._empty_ledger(), beat,
                        FakeVeldRpc(script=self.script), allocations,
                        candidate_btc, self.binding, 899_000,
                        self.policy, self.policy_hash)

    def test_proofless_mnp2_waits_for_canonical_c1_fund(self):
        self.register()
        allocations = self.registered_ledger()
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            100_000, 0, 0, 10, TIP_HASH, 1, 120), int(time.time()))

        class UnfundedRpc(FakeVeldRpc):
            def call(self, method, params=None):
                if method == "getbtcveldmintstatus":
                    return {
                        "outpoint": OUTPOINT, "consumed": False,
                        "minted": False, "proof_version": "MNP1",
                        "accepted_effect_kind": None,
                        "c1_allocation_id": None,
                        "tip": self.tip, "tip_hash": self.tip_hash,
                    }
                return super().call(method, params)

        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             self.assertRaises(SystemExit):
            witness.handle_reserve(
                self.request(), self.cfg, self.paths,
                witness._empty_ledger(), beat,
                UnfundedRpc(script=self.script), allocations,
                FakeBitcoin(self.script), self.binding, 899_000,
                self.policy, self.policy_hash)
        self.assertIsNotNone(
            allocations["allocations"][0]["deposit_observed_at"])
        self.assertIsNone(
            allocations["allocations"][0]["funded_reserved_at"])

        # MNP2 has no proof field.  A stale proof-bearing variant must not be
        # accepted as an alternate encoding of the same monetary effect.
        stale = self.decoded()
        decoded = json.loads(stale.stdout)
        decoded["memo"] += ";00"
        stale = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(decoded), stderr="")
        with mock.patch.object(witness.subprocess, "run", return_value=stale), \
             self.assertRaises(SystemExit):
            witness._derive_unsigned_mint(self.request(9), self.cfg)

    def test_funded_reorg_restart_refund_and_proofless_mnp2_recover(self):
        """A crash after C1F1 cannot strand or misidentify the allocation."""
        self.register()
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            100_000, 0, 0, 10, TIP_HASH, 1, 120), int(time.time()))
        funded_rpc = FakeVeldRpc(script=self.script)
        bitcoin = FakeBitcoin(self.script)

        # Simulate a process loss after the funded lifecycle checkpoint but
        # before any signer reservation/MNP2 receipt can be returned.
        allocations = self.registered_ledger()
        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             mock.patch.object(witness, "_sign_receipt",
                               side_effect=RuntimeError("simulated signer loss")), \
             self.assertRaisesRegex(RuntimeError, "simulated signer loss"):
            witness.handle_reserve(
                self.request(), self.cfg, self.paths,
                witness._empty_ledger(), beat, funded_rpc, allocations,
                bitcoin, self.binding, 899_000,
                self.policy, self.policy_hash)

        restarted = self.registered_ledger()
        row = restarted["allocations"][0]
        deposit_observed_at = row["deposit_observed_at"]
        self.assertIsNotNone(deposit_observed_at)
        self.assertIsNotNone(row["funded_reserved_at"])
        self.assertEqual(row["funding_outpoint"], OUTPOINT)
        self.assertEqual(
            witness._load_ledger(self.paths["ledger"], self.cfg)[
                "reservations"], [])

        class ReorgedFundingRpc(FakeVeldRpc):
            def call(self, method, params=None):
                if method == "getbtcveldc1reservation":
                    answer = super().call(method, params)
                    answer.update({
                        "funded": False, "funding_outpoint": None,
                        "funding_confirmations": None,
                        "funding_canonical_depth_reached": False,
                    })
                    return answer
                if method == "getbtcveldmintstatus":
                    return {
                        "outpoint": OUTPOINT,
                        "consumed": False, "minted": False,
                        "proof_version": "MNP1", "proof_hex": "00" * 32,
                        "root": "55" * 32, "count": 0,
                        "tip": self.tip, "tip_hash": self.tip_hash,
                        "accepted_txid": None,
                        "accepted_block_height": None,
                        "accepted_block_hash": None,
                        "accepted_tx_index": None,
                        "accepted_marker_vout": None,
                        "accepted_effect_kind": None,
                        "c1_allocation_id": None,
                        "consumer_txid": None,
                        "consumer_block_height": None,
                        "consumer_block_hash": None,
                        "consumer_tx_index": None,
                        "consumer_marker_vout": None,
                        "credit_txid": None,
                        "credit_block_height": None,
                        "credit_block_hash": None,
                        "credit_tx_index": None,
                        "credit_marker_vout": None,
                    }
                return super().call(method, params)

        # First retry after the shallow reorg checkpoints the exact rollback,
        # then correctly refuses MNP2 until a fresh C1F1 is canonical.
        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             self.assertRaises(SystemExit):
            witness.handle_reserve(
                self.request(), self.cfg, self.paths,
                witness._load_ledger(self.paths["ledger"], self.cfg), beat,
                ReorgedFundingRpc(script=self.script), restarted, bitcoin,
                self.binding, 899_000, self.policy, self.policy_hash)

        after_reorg = self.registered_ledger()
        row = after_reorg["allocations"][0]
        self.assertEqual(row["deposit_observed_at"], deposit_observed_at)
        self.assertIsNone(row["funded_reserved_at"])
        self.assertIsNone(row["funding_outpoint"])
        self.assertEqual(after_reorg["events"][-1]["action"],
                         "funded_reservation_reverted")

        # A fresh MNP1/C1F1 for the same still-unspent Bitcoin outpoint can be
        # observed after another restart, and only then reaches proofless MNP2.
        restarted_reservations = witness._load_ledger(
            self.paths["ledger"], self.cfg)
        signed_receipt = lambda core, cfg: {
            **core, "sig_alg": "mldsa65", "sig": "00"}
        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             mock.patch.object(witness, "_sign_receipt",
                               side_effect=signed_receipt):
            recovered = witness.handle_reserve(
                self.request(), self.cfg, self.paths, restarted_reservations,
                beat, funded_rpc, after_reorg, bitcoin, self.binding, 899_000,
                self.policy, self.policy_hash)
        self.assertFalse(recovered["idempotent"])
        self.assertEqual(recovered["receipt"]["allocation_request_id"],
                         self.allocation["consensus_allocation_id"])
        final = self.registered_ledger()
        self.assertEqual(final["allocations"][0]["funding_outpoint"], OUTPOINT)
        self.assertEqual(
            [event["action"] for event in final["events"]].count(
                "funded_reservation_observed"), 2)
        self.assertEqual(final["events"][-1]["action"],
                         "funded_reservation_observed")

        # A second F reorg after the signer reservation exists must preserve
        # that exact reservation/headroom charge while clearing only the
        # witness's funded timestamp/outpoint mirror.
        signed_state = witness._load_ledger(self.paths["ledger"], self.cfg)
        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             self.assertRaises(SystemExit):
            witness.handle_reserve(
                self.request(), self.cfg, self.paths, signed_state, beat,
                ReorgedFundingRpc(script=self.script), final, bitcoin,
                self.binding, 899_000, self.policy, self.policy_hash)
        self.assertEqual(len(signed_state["reservations"]), 1)
        self.assertEqual(signed_state["reservations"][0]["receipt"][
            "reservation_id"], recovered["receipt"]["reservation_id"])
        after_signed_reorg = self.registered_ledger()
        self.assertEqual(after_signed_reorg["allocations"][0][
            "deposit_observed_at"], deposit_observed_at)
        self.assertIsNone(after_signed_reorg["allocations"][0][
            "funded_reserved_at"])
        self.assertIsNone(after_signed_reorg["allocations"][0][
            "funding_outpoint"])
        self.assertEqual(len(witness._load_ledger(
            self.paths["ledger"], self.cfg)["reservations"]), 1)

        # One more restart + fresh C1F1 proves the recovered MNP2 reservation
        # remains idempotent and never double-charges headroom.
        with mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()), \
             mock.patch.object(witness, "_sign_receipt",
                               side_effect=signed_receipt):
            replay = witness.handle_reserve(
                self.request(), self.cfg, self.paths,
                witness._load_ledger(self.paths["ledger"], self.cfg), beat,
                funded_rpc, after_signed_reorg, bitcoin, self.binding, 899_000,
                self.policy, self.policy_hash)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["receipt"]["reservation_id"],
                         recovered["receipt"]["reservation_id"])
        final_recovered = self.registered_ledger()
        self.assertEqual(
            [event["action"] for event in final_recovered["events"]].count(
                "funded_reservation_observed"), 3)
        self.assertEqual(
            [event["action"] for event in final_recovered["events"]].count(
                "funded_reservation_reverted"), 2)

        # The accepted MNP2 effect is looked up by the consensus id, but its
        # durable allocation-journal event must remain keyed by the distinct
        # private retry id or the next restart rejects its own state.
        mint_txid = "99" * 32

        class MintedRpc(FakeVeldRpc):
            def call(self, method, params=None):
                answer = super().call(method, params)
                if method == "getbtcveldmintstatus":
                    answer.update({
                        "minted": True,
                        "accepted_effect_kind": "C1_MINT",
                        "accepted_txid": mint_txid,
                        "accepted_block_height": self.tip,
                        "accepted_block_hash": self.tip_hash,
                        "accepted_tx_index": 1,
                        "accepted_marker_vout": 0,
                        "credit_txid": mint_txid,
                        "credit_block_height": self.tip,
                        "credit_block_hash": self.tip_hash,
                        "credit_tx_index": 1,
                        "credit_marker_vout": 0,
                    })
                return answer

        committed = witness._load_ledger(self.paths["ledger"], self.cfg)
        committed["reservations"][0]["txid"] = mint_txid
        self.assertEqual(witness._reconcile(
            committed, beat, MintedRpc(script=self.script), self.cfg,
            self.paths, final_recovered, self.policy_hash,
            now=int(time.time()), c1_policy=self.policy), 0)
        after_mint_restart = self.registered_ledger()
        self.assertIsNotNone(after_mint_restart["allocations"][0]["minted_at"])
        self.assertEqual(after_mint_restart["events"][-1]["action"],
                         "mint_effect_observed")
        self.assertEqual(after_mint_restart["events"][-1]["request_id"],
                         self.allocation["request_id"])
        self.assertNotEqual(after_mint_restart["events"][-1]["request_id"],
                            self.allocation["consensus_allocation_id"])

    def test_unregistered_or_mutated_claim_cannot_reach_headroom_reservation(self):
        self.register()
        allocations = self.registered_ledger()
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            100_000, 0, 0, 10, TIP_HASH, 1, 120), int(time.time()))
        mutations = []
        absent = self.request()
        absent["allocation"]["request_id"] = "dd" * 16
        mutations.append(absent)
        wrong_outpoint = self.request()
        wrong_outpoint["allocation"]["deposit_outpoint"] = "66" * 32 + ":0"
        mutations.append(wrong_outpoint)
        wrong_address = self.request()
        wrong_address["allocation"]["btc_address"] = bech32m_address(
            self.binding["script_pubkeys"][2])
        mutations.append(wrong_address)
        for request in mutations:
            with mock.patch.object(witness.subprocess, "run",
                                   return_value=self.decoded()):
                with self.assertRaises(SystemExit):
                    witness.handle_reserve(
                        request, self.cfg, self.paths,
                        witness._empty_ledger(), beat,
                        FakeVeldRpc(script=self.script), allocations,
                        FakeBitcoin(self.script), self.binding, 899_000,
                        self.policy, self.policy_hash)

    def test_one_bitcoin_outpoint_and_allocation_bind_one_immutable_mint_template(self):
        self.register()
        allocations = self.registered_ledger()
        beat = sol.stamp_heartbeat(sol.build_beat_payload(
            200_000, 0, 0, 10, TIP_HASH, 1, 120), int(time.time()))
        ledger = witness._empty_ledger()
        with mock.patch.object(witness, "_sign_receipt",
                               side_effect=lambda core, cfg: {
                                   **core, "sig_alg": "mldsa65", "sig": "00"}), \
             mock.patch.object(witness.subprocess, "run",
                               return_value=self.decoded()):
            witness.handle_reserve(
                self.request(1), self.cfg, self.paths, ledger, beat,
                FakeVeldRpc(script=self.script, supply_sats=0),
                allocations, FakeBitcoin(self.script), self.binding,
                899_000, self.policy, self.policy_hash)
            with self.assertRaises(SystemExit):
                witness.handle_reserve(
                    self.request(2), self.cfg, self.paths, ledger, beat,
                    FakeVeldRpc(script=self.script, supply_sats=0),
                    allocations, FakeBitcoin(self.script), self.binding,
                    899_000, self.policy, self.policy_hash)

    def test_c1_retirement_requires_exact_effect_and_checkpoints_allocation(self):
        txid = "44" * 32
        beat = {"tip": 100, "tip_hash": TIP_HASH, "supply_sats": 0}
        allocation_id = "%032x" % 1

        class EffectRpc:
            phase = "UNCONSUMED"
            unavailable = False

            def call(self, method, params=None):
                if self.unavailable and method == "getbtcveldsupply":
                    raise RuntimeError("simulated index outage")
                if method == "getbtcveldsupply":
                    return {"supply_sats": 0, "tip": 100,
                            "tip_hash": TIP_HASH}
                if method == "getbtcveldmintstatus":
                    answer = {
                        "outpoint": OUTPOINT,
                        "consumed": self.phase != "UNCONSUMED",
                        "minted": self.phase == "C1_MINT",
                        "proof_version": "MNP1", "proof_hex": "00" * 32,
                        "root": "88" * 32, "count": 1, "tip": 100,
                        "tip_hash": TIP_HASH,
                        "accepted_txid": None,
                        "accepted_block_height": None,
                        "accepted_block_hash": None,
                        "accepted_tx_index": None,
                        "accepted_marker_vout": None,
                        "accepted_effect_kind": None,
                        "c1_allocation_id": None,
                        "consumer_txid": None,
                        "consumer_block_height": None,
                        "consumer_block_hash": None,
                        "consumer_tx_index": None,
                        "consumer_marker_vout": None,
                        "credit_txid": None,
                        "credit_block_height": None,
                        "credit_block_hash": None,
                        "credit_tx_index": None,
                        "credit_marker_vout": None,
                    }
                    if self.phase != "UNCONSUMED":
                        answer.update({
                            "accepted_txid": "77" * 32,
                            "accepted_block_height": 98,
                            "accepted_block_hash": "55" * 32,
                            "accepted_tx_index": 1,
                            "accepted_marker_vout": 0,
                            "accepted_effect_kind": (
                                "C1_MINT" if self.phase == "C1_MINT"
                                else "C1_FUND"),
                            "c1_allocation_id": allocation_id,
                            "consumer_txid": "77" * 32,
                            "consumer_block_height": 98,
                            "consumer_block_hash": "55" * 32,
                            "consumer_tx_index": 1,
                            "consumer_marker_vout": 0,
                        })
                    if self.phase == "C1_MINT":
                        answer.update({
                            "accepted_txid": txid,
                            "accepted_block_height": 99,
                            "accepted_block_hash": "55" * 32,
                            "accepted_tx_index": 2,
                            "accepted_marker_vout": 0,
                            "credit_txid": txid,
                            "credit_block_height": 99,
                            "credit_block_hash": "55" * 32,
                            "credit_tx_index": 2,
                            "credit_marker_vout": 0,
                        })
                    return answer
                if method == "getblockhash":
                    return "55" * 32
                raise AssertionError(method)

        rpc = EffectRpc()
        receipt = {
            "v": sol.C1_RESERVATION_VERSION,
            "deposit_outpoint": OUTPOINT,
            "allocation_request_id": allocation_id,
            "allocation_btc_address": self.address,
            "allocation_script_pubkey": self.script,
            "sats": 62_500, "recipient": RECIPIENT,
        }
        entry = {"receipt": receipt, "status": "reserved", "txid": txid,
                 "signed_tx_sha256": "66" * 32}
        ledger = {"reservations": [entry]}
        allocation = {"request_id": "aa" * 16,
                      "consensus_allocation_id": allocation_id,
                      "btc_address": self.address,
                      "script_pubkey": self.script,
                      "amount_sats": 62_500,
                      "veld_address": RECIPIENT,
                      "deposit_observed_at": 9,
                      "funded_reserved_at": 10,
                      "funding_outpoint": OUTPOINT,
                      "minted_at": None}
        authority = {"allocations": [allocation], "events": []}
        policy = dict(witness.C1_POLICY_EXACT)

        self.assertEqual(witness._reconcile(ledger, beat, rpc), 62_500)
        self.assertEqual(entry["status"], "reserved")
        rpc.phase = "C1_FUND"
        self.assertEqual(witness._reconcile(ledger, beat, rpc), 62_500)
        self.assertEqual(entry["status"], "reserved")
        rpc.phase = "C1_MINT"
        with mock.patch.object(witness, "atomic_write") as write, \
             mock.patch.object(witness, "_checkpoint_allocation_ledger") as checkpoint, \
             mock.patch.object(witness, "_require_restore_clear"):
            self.assertEqual(witness._reconcile(
                ledger, beat, rpc, self.cfg, self.paths, authority,
                "77" * 32, now=20, c1_policy=policy), 0)
            self.assertEqual(allocation["minted_at"], 20)
            self.assertEqual(entry["status"], "confirmed")
            self.assertEqual(authority["events"][-1]["action"],
                             "mint_effect_observed")
            self.assertEqual(authority["events"][-1]["request_id"],
                             allocation["request_id"])
            write.assert_called()
            checkpoint.assert_called()

            rpc.unavailable = True
            with self.assertRaises(SystemExit):
                witness._reconcile(
                    ledger, beat, rpc, self.cfg, self.paths, authority,
                    "77" * 32, now=21, c1_policy=policy)
            self.assertEqual(allocation["minted_at"], 20)
            self.assertEqual(authority["events"][-1]["action"],
                             "mint_effect_observed")
            rpc.unavailable = False

            rpc.phase = "C1_FUND"
            self.assertEqual(witness._reconcile(
                ledger, beat, rpc, self.cfg, self.paths, authority,
                "77" * 32, now=22, c1_policy=policy), 62_500)
            self.assertIsNone(allocation["minted_at"])
            self.assertEqual(entry["status"], "reserved")
            self.assertEqual(authority["events"][-1]["action"],
                             "mint_effect_reverted")
            self.assertEqual(authority["events"][-1]["request_id"],
                             allocation["request_id"])
        self.assertEqual(len(ledger["reservations"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
