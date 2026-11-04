#!/usr/bin/env python3
"""Anchor relay confirmation and Bitcoin-depth boundary regressions."""

import json
import os
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from swap import veld_anchord as anchord


class HoldBtc:
    def __init__(self, confirmations):
        self.confirmations = confirmations

    def call(self, method, *args):
        if method == "gettransaction":
            return {"confirmations": self.confirmations}
        raise AssertionError(method)


class AnchorInfoVeld:
    def __init__(self, high_water=0, final_height=100, anchor_active=True, finality_active=True):
        self.high_water = high_water
        self.final_height = final_height
        self.anchor_active = anchor_active
        self.finality_active = finality_active

    def rpc(self, method, params=None):
        if method == "getanchorinfo":
            return {
                "anchor_active": self.anchor_active,
                "anchor_admission_live": self.anchor_active,
                "anchor_checkpoint_enforced": self.high_water > 0,
                "anchor_security_milestone": self.high_water > 0,
                "anchor_configured": True,
                "finality_active": self.finality_active,
                "final_height": self.final_height,
                "high_water": self.high_water,
                "k_btc": 6,
            }
        raise AssertionError(method)


class TemplateBtc:
    """Minimal exact-template Bitcoin wallet used by signed-vsize tests."""

    def __init__(self, vsize=250):
        self.outputs_json = None
        self.fees = []
        self.vsize = vsize
        self.tx_hex = "0100000000"
        self.txid = anchord.dsha(bytes.fromhex(self.tx_hex))[::-1].hex()

    def call(self, method, *args):
        fund_spk = "76a914" + "11" * 20 + "88ac"
        if method == "getaddressinfo":
            return {
                "scriptPubKey": fund_spk,
                "ismine": True,
                "solvable": True,
                "iswatchonly": False,
            }
        if method == "listunspent":
            return [
                {
                    "txid": "22" * 32,
                    "vout": 7,
                    "amount": Decimal("0.01000001"),
                    "spendable": True,
                    "solvable": True,
                    "safe": True,
                    "scriptPubKey": fund_spk,
                }
            ]
        if method == "createrawtransaction":
            self.outputs_json = args[1]
            outputs = json.loads(self.outputs_json, parse_float=Decimal)
            change = next(iter(outputs[1].values()))
            self.fees.append(1_000_001 - anchord.btc_amount_to_sats(change))
            return "unsigned"
        if method == "signrawtransactionwithwallet":
            return {"complete": True, "hex": self.tx_hex}
        if method == "decoderawtransaction":
            outputs = json.loads(self.outputs_json, parse_float=Decimal)
            data = bytes.fromhex(outputs[0]["data"])
            change = next(iter(outputs[1].values()))
            return {
                "txid": self.txid,
                "vsize": self.vsize,
                "vin": [{"txid": "22" * 32, "vout": 7}],
                "vout": [
                    {
                        "value": Decimal(0),
                        "scriptPubKey": {"hex": (b"\x6a" + bytes([len(data)]) + data).hex()},
                    },
                    {"value": change, "scriptPubKey": {"hex": fund_spk}},
                ],
            }
        raise AssertionError(method)


class FreshnessBtc:
    def __init__(self, age, *, chain="main", ibd=False, blocks=100, headers=100):
        self.age = age
        self.chain = chain
        self.ibd = ibd
        self.blocks = blocks
        self.headers = headers
        self.best = "55" * 32

    def call(self, method, *args):
        if method == "getblockchaininfo":
            return {
                "chain": self.chain,
                "initialblockdownload": self.ibd,
                "blocks": self.blocks,
                "headers": self.headers,
                "bestblockhash": self.best,
            }
        if method == "getblockheader":
            self.assert_args = args
            return {
                "hash": self.best,
                "height": self.blocks,
                "confirmations": 1,
                "time": 100_000 - self.age,
            }
        raise AssertionError(method)


class AnchorStateTests(unittest.TestCase):
    def test_bitcoin_tip_age_is_measured_from_a_coherent_synced_tip(self):
        a = object.__new__(anchord.Anchor)
        a.production = True
        a.btc = FreshnessBtc(3599)
        with mock.patch.object(anchord.time, "time", return_value=100_000):
            self.assertEqual(a.btc_tip_age(), 3599)
        self.assertEqual(a.btc.assert_args, ("55" * 32, True))

    def test_bitcoin_tip_freshness_rejects_wrong_chain_ibd_and_header_lag(self):
        for btc in (
            FreshnessBtc(1, chain="test"),
            FreshnessBtc(1, ibd=True),
            FreshnessBtc(1, headers=101),
        ):
            a = object.__new__(anchord.Anchor)
            a.production = True
            a.btc = btc
            with self.assertRaises(RuntimeError):
                with mock.patch.object(anchord.time, "time", return_value=100_000):
                    a.btc_tip_age()

    def test_core_confirmation_count_is_consensus_k_plus_one(self):
        a = object.__new__(anchord.Anchor)
        a.k_btc = 6
        a.regtest_generate = False
        a.btc = HoldBtc(6)
        self.assertEqual(a.required_core_confirmations(), 7)
        self.assertIsNone(a.try_relay(10, {"btc_txid": "ab" * 32}))

    def make_anchor(self, td):
        a = object.__new__(anchord.Anchor)
        a.veld = AnchorInfoVeld(0, final_height=10)
        a.production = True
        a.k_btc = 6
        a.relay_resubmit_secs = 3600
        a.state_path = str(Path(td) / "anchor_state.json")
        a.state = {
            "anchors": {
                "10": {"status": "committed", "btc_txid": "ab" * 32, "veld_hash": "cd" * 32}
            }
        }
        a.veld_tip = lambda: (10, True)
        a.try_relay = lambda height, rec: "ef" * 32
        a.btc_tip_age = lambda: 0
        a.tip_age_alert_secs = 3600
        a.max_tip_age_secs = 7200
        a.btc_feerate_sat_vb = lambda: Decimal(1)
        a.min_spacing = 480
        a.deadline_blocks = 960
        a.fee_cheap_svb = Decimal(5)
        a.fee_ceiling_svb = Decimal(50)
        a.cfg = {}
        return a

    def test_send_is_submitted_until_consensus_high_water_advances(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            a.run_once()
            rec = a.state["anchors"]["10"]
            self.assertEqual(rec["status"], "submitted")
            submitted_at = rec["submitted_at"]

            # Recent submission is not re-sent and is not called confirmed.
            a.try_relay = lambda *_: self.fail("recent submission was retried")
            a.run_once()
            self.assertEqual(rec["status"], "submitted")
            self.assertEqual(rec["submitted_at"], submitted_at)

            # Canonical module state is the sole completion authority.
            a.veld.high_water = 10
            a.run_once()
            self.assertEqual(rec["status"], "confirmed")

    def test_no_bitcoin_spend_before_real_validator_finality(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            a.veld.anchor_active = False
            a.veld.finality_active = False
            a.veld.final_height = 0
            a.try_relay = lambda *_: self.fail("pre-finality relay attempted")
            a.btc_feerate_sat_vb = lambda: self.fail("pre-finality Bitcoin fee quote attempted")
            before = json.loads(json.dumps(a.state))
            a.run_once()
            self.assertEqual(a.state, before)

    def test_new_anchor_target_is_capped_at_validator_final_height(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            a.state = {"anchors": {}}
            a.veld.final_height = 90
            a.veld_tip = lambda: (100, True)
            a.commit_fee_sats = lambda _: 400
            a.veld_block_hash = lambda height: (self.assertEqual(height, 90) or "44" * 32)
            prepared = []
            a.prepare_btc_commit = lambda height, vhash, fee, rate: (
                prepared.append(height)
                or {
                    "veld_hash": vhash,
                    "btc_txid": "ab" * 32,
                    "btc_tx_hex": "0100000000",
                    "status": "prepared",
                    "at": 1,
                    "fee_sats": fee,
                    "feerate_sat_vb": str(rate),
                }
            )
            a.broadcast_prepared = lambda rec: rec["btc_txid"]
            a.try_relay = lambda *_: None
            a.run_once()
            self.assertEqual(prepared, [90])

    def test_inconsistent_active_rpc_without_finality_fails_closed(self):
        a = object.__new__(anchord.Anchor)
        a.veld = AnchorInfoVeld(final_height=0, anchor_active=True, finality_active=False)
        a.k_btc = 6
        with self.assertRaisesRegex(RuntimeError, "without real validator finality"):
            a.consensus_anchor_info()

    def test_legacy_relayed_record_without_consensus_is_retried(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            rec = a.state["anchors"]["10"]
            rec["status"] = "relayed"
            a.run_once()
            self.assertEqual(rec["status"], "submitted")
            self.assertEqual(rec["veld_op_txid"], "ef" * 32)

    def test_exact_satoshi_conversion_and_json_never_use_float(self):
        self.assertEqual(anchord.btc_amount_to_sats(Decimal("0.01000001")), 1_000_001)
        self.assertEqual(anchord.sats_json_number(1_000_001), "0.01000001")
        with self.assertRaisesRegex(RuntimeError, "exact"):
            anchord.btc_amount_to_sats("0.000000001")

    def test_prepare_builds_exact_change_fee_and_legacy_opreturn(self):
        a = object.__new__(anchord.Anchor)
        a.btc = TemplateBtc()
        a.btc_fund_addr = "1LegacyAddress"
        a.max_fee_sats = 20_000
        a.max_vsize = 400
        a.fee_ceiling_svb = Decimal(50)
        rec = a.prepare_btc_commit(5, "33" * 32, 260, Decimal("1"))
        self.assertEqual(rec["status"], "prepared")
        self.assertEqual(rec["fee_sats"], 250)
        self.assertEqual(a.btc.fees, [260, 250])
        self.assertIn('"1LegacyAddress":0.00999751', a.btc.outputs_json)

    def test_prepare_rejects_actual_signed_vsize_above_hard_ceiling(self):
        a = object.__new__(anchord.Anchor)
        a.btc = TemplateBtc(vsize=401)
        a.btc_fund_addr = "1LegacyAddress"
        a.max_fee_sats = 20_000
        a.max_vsize = 400
        a.fee_ceiling_svb = Decimal(50)
        with self.assertRaisesRegex(RuntimeError, "400-vB policy ceiling"):
            a.prepare_btc_commit(5, "33" * 32, 400, Decimal("1"))

    def test_prepared_record_is_fsynced_before_first_broadcast_and_resumes_exactly(self):
        with tempfile.TemporaryDirectory() as td:
            os.chmod(td, 0o700)
            a = object.__new__(anchord.Anchor)
            a.state_path = str(Path(td) / "anchor_state.json")
            a.state = {"anchors": {}}
            a.veld = AnchorInfoVeld(0, final_height=100)
            a.production = True
            a.k_btc = 6
            a.veld_tip = lambda: (100, True)
            a.btc_tip_age = lambda: 0
            a.tip_age_alert_secs = 3600
            a.max_tip_age_secs = 7200
            a.relay_resubmit_secs = 3600
            a.min_spacing = 480
            a.deadline_blocks = 960
            a.cfg = {}
            a.fee_cheap_svb = Decimal(5)
            a.fee_ceiling_svb = Decimal(50)
            a.btc_feerate_sat_vb = lambda: Decimal(1)
            a.commit_fee_sats = lambda _: 400
            a.veld_block_hash = lambda _: "44" * 32
            raw = "0100000000"
            txid = anchord.dsha(bytes.fromhex(raw))[::-1].hex()
            a.prepare_btc_commit = lambda *args: {
                "veld_hash": "44" * 32,
                "btc_txid": txid,
                "btc_tx_hex": raw,
                "status": "prepared",
                "at": 1,
                "fee_sats": 400,
                "feerate_sat_vb": "1",
            }

            def ambiguous(_):
                on_disk = anchord.load_anchor_state(a.state_path)
                self.assertEqual(on_disk["anchors"]["100"]["status"], "prepared")
                self.assertEqual(on_disk["anchors"]["100"]["btc_tx_hex"], raw)
                raise RuntimeError("simulated lost send response")

            a.broadcast_prepared = ambiguous
            with self.assertRaisesRegex(RuntimeError, "lost send"):
                a.run_once()
            self.assertEqual(
                anchord.load_anchor_state(a.state_path)["anchors"]["100"]["status"], "prepared"
            )

            sent = []
            a.broadcast_prepared = lambda rec: sent.append(rec["btc_tx_hex"]) or rec["btc_txid"]
            a.try_relay = lambda *_: None
            a.run_once()
            self.assertEqual(sent, [raw])
            self.assertEqual(
                anchord.load_anchor_state(a.state_path)["anchors"]["100"]["status"], "committed"
            )

    def test_c5_boundaries_gate_only_new_anchor_admission(self):
        with tempfile.TemporaryDirectory() as td:
            for age, admitted in (
                (3599, True),
                (3600, True),
                (7199, True),
                (7200, False),
                (7201, False),
            ):
                a = self.make_anchor(td)
                a.state = {"anchors": {}}
                a.veld.final_height = 100
                a.veld_tip = lambda: (100, True)
                a.btc_tip_age = lambda age=age: age
                a.veld_block_hash = lambda _: "44" * 32
                a.commit_fee_sats = lambda _: 400
                prepared = []
                a.prepare_btc_commit = lambda height, vhash, fee, rate: (
                    prepared.append(height)
                    or {
                        "veld_hash": vhash,
                        "btc_txid": "ab" * 32,
                        "btc_tx_hex": "0100000000",
                        "status": "prepared",
                        "at": 1,
                        "fee_sats": fee,
                        "feerate_sat_vb": str(rate),
                    }
                )
                a.broadcast_prepared = lambda rec: rec["btc_txid"]
                a.run_once()
                self.assertEqual(bool(prepared), admitted, f"tip age {age}")

    def test_c5_hard_threshold_allows_inflight_relay_to_continue(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            a.btc_tip_age = lambda: 7200
            a.run_once()
            self.assertEqual(a.state["anchors"]["10"]["status"], "submitted")

    def test_fee_above_owner_ceiling_is_skipped_even_at_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            a = self.make_anchor(td)
            a.state["anchors"]["10"]["status"] = "confirmed"
            a.veld.high_water = 10
            a.veld.final_height = 1000
            a.veld_tip = lambda: (1000, True)
            a.btc_feerate_sat_vb = lambda: Decimal(51)
            a.prepare_btc_commit = lambda *_: self.fail(
                "above-ceiling deadline created a Bitcoin transaction"
            )
            a.run_once()
            self.assertNotIn("1000", a.state["anchors"])


class AnchorProductionConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.bitcoin_dir = self.root / "bitcoin"
        self.bitcoin_dir.mkdir(mode=0o700)
        self.veld_dir = self.root / "veld"
        self.veld_dir.mkdir(mode=0o700)
        self.bitcoin = self._exe("bitcoin-cli")
        self.node = self._exe("veld-node")
        self.keygen = self._exe("veld-keygen")
        self.keyfile = self.state / "anchor.key"
        self.keyfile.write_bytes(b"encrypted-test-key")
        os.chmod(self.keyfile, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def _exe(self, name):
        path = self.root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        os.chmod(path, 0o755)
        return path

    def config(self):
        return {
            "production": True,
            "state_dir": str(self.state),
            "cli_base": [str(self.bitcoin), "-datadir=" + str(self.bitcoin_dir)],
            "btc_wallet": "veld-anchor-fees",
            "btc_rpc_timeout": 30,
            "veld_rpc": {
                "url": "http://127.0.0.1:8334",
                "token_cmd": [
                    str(self.node),
                    "--datadir=" + str(self.veld_dir),
                    "--print-rpc-token",
                ],
            },
            "fund_addr": "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg",
            "btc_fund_addr": "1LegacyAnchorAddress",
            "signer": {"keygen": str(self.keygen), "keyfile": str(self.keyfile)},
            "k_btc": 6,
            "relay_resubmit_timeout_secs": 3600,
            "anchor_tx_vsize": 400,
            "fee_conf_target": 6,
            "fee_fallback_sat_vb": 20,
            "max_fee_sats": 20000,
            "anchor_deadline_blocks": 960,
            "anchor_min_spacing_blocks": 480,
            "fee_cheap_sat_vb": 5,
            "fee_ceiling_sat_vb": 50,
            "tip_age_alert_secs": 3600,
            "max_tip_age_secs": 7200,
            "regtest_generate": False,
        }

    def test_production_policy_is_explicit_and_relationally_validated(self):
        self.assertIs(anchord.validate_config(self.config())["production"], True)
        cfg = self.config()
        del cfg["max_fee_sats"]
        with self.assertRaisesRegex(RuntimeError, "every fee/cadence"):
            anchord.validate_config(cfg)
        cfg = self.config()
        cfg["max_fee_sats"] = 100
        with self.assertRaisesRegex(RuntimeError, "at least 1 sat"):
            anchord.validate_config(cfg)
        cfg = self.config()
        cfg["anchor_min_spacing_blocks"] = 961
        with self.assertRaisesRegex(RuntimeError, "must not exceed"):
            anchord.validate_config(cfg)
        cfg = self.config()
        cfg["regtest_generate"] = True
        with self.assertRaisesRegex(RuntimeError, "forbids"):
            anchord.validate_config(cfg)

    def test_production_policy_is_pinned_and_anchor_lag_is_retired(self):
        for field, bad in (
            ("k_btc", 5),
            ("relay_resubmit_timeout_secs", 600),
            ("anchor_tx_vsize", 401),
            ("fee_conf_target", 7),
            ("fee_fallback_sat_vb", 19),
            ("max_fee_sats", 19999),
            ("anchor_deadline_blocks", 959),
            ("anchor_min_spacing_blocks", 479),
            ("fee_cheap_sat_vb", 4),
            ("fee_ceiling_sat_vb", 51),
            ("tip_age_alert_secs", 3599),
            ("max_tip_age_secs", 7201),
        ):
            cfg = self.config()
            cfg[field] = bad
            with self.assertRaises(RuntimeError, msg=field):
                anchord.validate_config(cfg)
        cfg = self.config()
        cfg["anchor_lag"] = 2
        with self.assertRaisesRegex(RuntimeError, "anchor_lag is retired"):
            anchord.validate_config(cfg)

    def test_state_dir_and_state_file_fail_closed(self):
        path = self.state / "anchor_state.json"
        anchord.save_json(str(path), {"anchors": {}})
        self.assertEqual(anchord.load_anchor_state(str(path)), {"anchors": {}})
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(RuntimeError, "mode-0600"):
            anchord.load_anchor_state(str(path))
        os.chmod(path, 0o600)
        os.chmod(self.state, 0o755)
        with self.assertRaisesRegex(RuntimeError, "mode-0700"):
            anchord._secure_state_dir(str(self.state))

    def test_shipped_service_config_and_runbook_are_launch_bound(self):
        deploy = Path(__file__).parent / "deploy"
        unit = (deploy / "veld-anchord.service").read_text(encoding="utf-8")
        example = json.loads((deploy / "anchord.example.json").read_text(encoding="utf-8"))
        runbook = (deploy / "ANCHOR-RUNBOOK.md").read_text(encoding="utf-8")
        for marker in (
            "User=veldanchor",
            "StateDirectory=veld-anchord",
            "StateDirectoryMode=0700",
            "ProtectSystem=strict",
            "UMask=0077",
            "--loop 30",
        ):
            self.assertIn(marker, unit)
        self.assertTrue(example["production"])
        approved = {
            "k_btc": 6,
            "relay_resubmit_timeout_secs": 3600,
            "anchor_tx_vsize": 400,
            "fee_conf_target": 6,
            "fee_fallback_sat_vb": 20,
            "max_fee_sats": 20000,
            "anchor_deadline_blocks": 960,
            "anchor_min_spacing_blocks": 480,
            "fee_cheap_sat_vb": 5,
            "fee_ceiling_sat_vb": 50,
            "tip_age_alert_secs": 3600,
            "max_tip_age_secs": 7200,
        }
        for field, value in approved.items():
            self.assertEqual(example[field], value, field)
        self.assertNotIn("anchor_lag", example)
        for marker in (
            "production launch policy",
            "prepared",
            "fsync",
            "getanchorinfo.high_water",
            "actual signed vsize",
            "recovery-only",
            "A failure or missing check",
        ):
            self.assertIn(marker, runbook)


if __name__ == "__main__":
    unittest.main(verbosity=2)
