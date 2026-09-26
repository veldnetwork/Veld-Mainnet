#!/usr/bin/env python3
"""Independent threshold signer observation/policy regressions."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swap import veld_payout_signerd as ps
from swap import veld_redeemd as rd


TEST_DESCRIPTOR = json.loads(
    (Path(__file__).parent / "fixtures" / "custody-policy-descriptor.json").read_text()
)["descriptor"]


BURN = {
    "burn_txid": "12" * 32,
    "opreturn_vout": 1,
    "redeemer": "V" + "2" * 33,
    "amount_sats": 77_000,
    "burn_height": 55,
    "burn_block_hash": "34" * 32,
    "dest_btc_addr": "0014" + "56" * 20,
}


class FeedVeld:
    def __init__(self, records):
        self.records = list(records)

    def call(self, method, params=None):
        if method != "getbtcveldredeems":
            raise AssertionError(method)
        cursor = (params or [""])[0]
        rows = [
            {
                "txid": x["burn_txid"],
                "vout": x["opreturn_vout"],
                "from": x["redeemer"],
                "to": "",
                "amount_sats": x["amount_sats"],
                "block": x["burn_height"],
                "block_hash": x["burn_block_hash"],
                "memo": x["dest_btc_addr"],
                "token": "btcVELD",
                "is_mint": False,
                "is_burn": False,
                "is_redeem": True,
            }
            for x in self.records
        ]
        return {
            "tip": 60,
            "tip_hash": "aa" * 32,
            "final_height": 60,
            "cursor": cursor,
            "next_cursor": cursor,
            "has_more": False,
            "page_limit": 512,
            "redeems": rows,
            **rd.authority_for_rows(rows),
        }


class SigningVeld:
    def call(self, method, params=None):
        if method == "getblockcount":
            return 200
        if method == "getblockchaininfo":
            return {"max_reorg_depth": rd.MAX_REORG_DEPTH}
        if method == "getpeginfo":
            return {
                "active": True,
                "spv_active": True,
                "final_height": 200,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_descriptor_range": [0, 999],
                "spv_custody_descriptor_index": 0,
                "spv_custody_spk_hex": SigningBtc.CUSTODY_SPK,
            }
        if method == "getblockhash":
            return BURN["burn_block_hash"]
        if method == "gettransaction":
            return {"txid": BURN["burn_txid"], "block_hash": BURN["burn_block_hash"]}
        raise AssertionError(method)


class RacingSigningVeld(SigningVeld):
    def __init__(self):
        self.tip_calls = 0

    def call(self, method, params=None):
        if method == "getblockcount":
            self.tip_calls += 1
            return 200 if self.tip_calls == 1 else 201
        if method == "getblockhash" and params[0] in (200, 201):
            return ("aa" if params[0] == 200 else "bb") * 32
        return super().call(method, params)


class MismatchedDepthSigningVeld(SigningVeld):
    def call(self, method, params=None):
        if method == "getblockchaininfo":
            return {"max_reorg_depth": rd.MAX_REORG_DEPTH + 1}
        return super().call(method, params)


class SigningBtc:
    INPUT_TXID = "78" * 32
    CUSTODY_SPK = "5120" + "9a" * 32

    def __init__(self):
        self.psbt_sighash = "ALL"
        self.psbt_extra = {}
        self.tx_version = 2
        self.tx_locktime = 0
        self.tx_sequence = 0xFFFFFFFF
        self.tx_script_sig = ""
        self.tx_witness = None
        self.wallet_sign_calls = 0

    def call(self, method, *args):
        if method == "decoderawtransaction":
            raw = args[0]
            txin = {
                "txid": self.INPUT_TXID,
                "vout": 0,
                "sequence": self.tx_sequence,
                "scriptSig": {"hex": self.tx_script_sig},
            }
            if self.tx_witness is not None:
                txin["txinwitness"] = self.tx_witness
            return {
                "txid": ("bc" * 32 if raw == "aa" else "de" * 32),
                "version": self.tx_version,
                "locktime": self.tx_locktime,
                "vin": [txin],
                "vout": [
                    {
                        "value": rd.btc_str(BURN["amount_sats"]),
                        "scriptPubKey": {"hex": BURN["dest_btc_addr"]},
                    },
                    {"value": "0.00000000", "scriptPubKey": {"hex": rd.payout_marker_script(BURN)}},
                ],
            }
        if method == "decodepsbt":
            entry = dict(self.psbt_extra)
            if self.psbt_sighash is not None:
                entry["sighash"] = self.psbt_sighash
            return {
                "tx": {"txid": "bc" * 32 if args[0] == "psbt-a" else "de" * 32},
                "inputs": [entry],
            }
        if method == "gettxout":
            return {
                "value": rd.btc_str(BURN["amount_sats"] + 1000),
                "confirmations": 12,
                "scriptPubKey": {"hex": self.CUSTODY_SPK},
            }
        if method == "walletprocesspsbt":
            self.wallet_sign_calls += 1
            return {"psbt": "partial-from-s1", "complete": False}
        raise AssertionError(method)


_FULL_CUSTODY_SCRIPTS = None


def full_custody_scripts():
    global _FULL_CUSTODY_SCRIPTS
    if _FULL_CUSTODY_SCRIPTS is None:
        _FULL_CUSTODY_SCRIPTS = [SigningBtc.CUSTODY_SPK] + [
            "5120%064x" % i for i in range(1, 11000)
        ]
    return list(_FULL_CUSTODY_SCRIPTS)


def public_custody_cfg(scripts=None):
    scripts = list(scripts or full_custody_scripts())
    return {
        "signer_id": "s1",
        "custody_descriptor": TEST_DESCRIPTOR,
        "custody_descriptor_sha256": "ab" * 32,
        "custody_manifest_sha256": "cd" * 32,
        "custody_consensus_manifest_sha256": "cd" * 32,
        "custody_script_range": [0, 10999],
        "custody_script_pubkeys": scripts,
        "btc_input_confirmations": 6,
        "max_payout_fee_sats": 2000,
    }


class CanonicalC1Veld:
    """Stable Veld authority with a configurable public C1 credit depth."""

    TIP_HASH = "aa" * 32
    CONSUMER_HASH = "bb" * 32
    CREDIT_HASH = "cc" * 32
    CONSUMER_TXID = "77" * 32
    CREDIT_TXID = "88" * 32
    ALLOCATION_ID = "%032x" % 1

    def __init__(
        self,
        operator_spk=SigningBtc.CUSTODY_SPK,
        credit_depth=101,
        phase="C1_MINT",
        race_after_first_status=False,
    ):
        self.operator_spk = operator_spk
        self.tip = 300
        self.credit_depth = credit_depth
        self.phase = phase
        self.race_after_first_status = race_after_first_status
        self.status_calls = 0
        self.canonical = True

    @property
    def credit_height(self):
        return self.tip - self.credit_depth

    def _status(self, outpoint):
        self.status_calls += 1
        phase = self.phase
        if self.race_after_first_status and self.status_calls > 1:
            phase = "C1_FUND"
        answer = {
            "outpoint": outpoint,
            "consumed": phase != "UNCONSUMED",
            "minted": phase == "C1_MINT",
            "proof_version": "MNP1",
            "proof_hex": "00" * 32,
            "root": "99" * 32,
            "count": 1,
            "tip": self.tip,
            "tip_hash": self.TIP_HASH,
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
        if phase != "UNCONSUMED":
            answer.update(
                {
                    "accepted_txid": self.CONSUMER_TXID,
                    "accepted_block_height": 150,
                    "accepted_block_hash": self.CONSUMER_HASH,
                    "accepted_tx_index": 1,
                    "accepted_marker_vout": 0,
                    "accepted_effect_kind": "C1_FUND",
                    "c1_allocation_id": self.ALLOCATION_ID,
                    "consumer_txid": self.CONSUMER_TXID,
                    "consumer_block_height": 150,
                    "consumer_block_hash": self.CONSUMER_HASH,
                    "consumer_tx_index": 1,
                    "consumer_marker_vout": 0,
                }
            )
        if phase == "C1_MINT":
            answer.update(
                {
                    "accepted_txid": self.CREDIT_TXID,
                    "accepted_block_height": self.credit_height,
                    "accepted_block_hash": self.CREDIT_HASH,
                    "accepted_tx_index": 2,
                    "accepted_marker_vout": 0,
                    "accepted_effect_kind": "C1_MINT",
                    "credit_txid": self.CREDIT_TXID,
                    "credit_block_height": self.credit_height,
                    "credit_block_hash": self.CREDIT_HASH,
                    "credit_tx_index": 2,
                    "credit_marker_vout": 0,
                }
            )
        return answer

    def call(self, method, params=None):
        if method == "getbtcveldsupply":
            return {"supply_sats": 77_000, "tip": self.tip, "tip_hash": self.TIP_HASH}
        if method == "getbtcveldmintstatus":
            return self._status(params[0])
        if method == "getblockcount":
            return self.tip
        if method == "getblockchaininfo":
            return {"max_reorg_depth": rd.MAX_REORG_DEPTH}
        if method == "getpeginfo":
            return {
                "active": True,
                "spv_active": True,
                "final_height": self.tip,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_descriptor_range": [0, 999],
                "spv_custody_descriptor_index": 0,
                "spv_custody_spk_hex": self.operator_spk,
            }
        if method == "getblockhash":
            height = params[0]
            if height == BURN["burn_height"]:
                return BURN["burn_block_hash"]
            if height == self.tip:
                return self.TIP_HASH
            if height == 150:
                return self.CONSUMER_HASH
            if height == self.credit_height:
                return self.CREDIT_HASH if self.canonical else "dd" * 32
            raise AssertionError((method, params))
        if method == "gettransaction":
            return {"txid": BURN["burn_txid"], "block_hash": BURN["burn_block_hash"]}
        raise AssertionError(method)


class PayoutSignerPolicyTests(unittest.TestCase):
    @staticmethod
    def _burn(i):
        r = dict(BURN)
        r["burn_txid"] = "%064x" % (i + 1)
        r["opreturn_vout"] = i % 3
        r["burn_height"] = 55 + i // 100
        r["burn_block_hash"] = "%064x" % (100000 + r["burn_height"])
        return r

    def test_signer_observes_only_its_own_accepted_feed_then_persists(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            cfg = {"signer_id": "s1"}
            first = ps.observe({"records": [BURN]}, cfg, store, FeedVeld([BURN]))
            self.assertEqual(first["observed"], [rd.redeem_id(BURN)])
            # Once independently observed and fsynced, the signer still knows the
            # immature burn after it ages out of the node's bounded feed.
            again = ps.observe({"records": [BURN]}, cfg, store, FeedVeld([]))
            self.assertEqual(again["observed"], [rd.redeem_id(BURN)])
            self.assertEqual(len(store.all_records()), 1)
            store.close()

    def test_new_record_absent_from_independent_feed_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            with self.assertRaises(SystemExit) as cm:
                ps.observe({"records": [BURN]}, {"signer_id": "s1"}, store, FeedVeld([]))
            self.assertEqual(cm.exception.code, 2)
            self.assertEqual(store.all_records(), [])
            store.close()

    def test_coordinator_requires_durable_observation_quorum(self):
        cfg = {
            "mode": "threshold_psbt",
            "threshold": 2,
            "signers": [
                {"id": "s1", "command": ["signer-one"]},
                {"id": "s2", "command": ["signer-two"]},
                {"id": "s3", "command": ["signer-three"]},
            ],
        }
        rid = rd.redeem_id(BURN)

        def ok_run(cmd, **kwargs):
            sid = {"signer-one": "s1", "signer-two": "s2", "signer-three": "s3"}[cmd[0]]
            return subprocess.CompletedProcess(
                cmd, 0, stdout=json.dumps({"signer_id": sid, "observed": [rid]}), stderr=""
            )

        with mock.patch.object(rd.subprocess, "run", side_effect=ok_run):
            ack = rd.replicate_observations(cfg, [BURN])
        self.assertEqual(ack, ["s1", "s2", "s3"])

    def test_coordinator_holds_when_observation_quorum_is_missing(self):
        cfg = {
            "mode": "threshold_psbt",
            "threshold": 2,
            "signers": [
                {"id": "s1", "command": ["signer-one"]},
                {"id": "s2", "command": ["signer-two"]},
            ],
        }
        rid = rd.redeem_id(BURN)

        def one_only(cmd, **kwargs):
            if cmd[0] == "signer-one":
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=json.dumps({"signer_id": "s1", "observed": [rid]}), stderr=""
                )
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="refuse")

        with mock.patch.object(rd.subprocess, "run", side_effect=one_only):
            with self.assertRaisesRegex(RuntimeError, "quorum incomplete"):
                rd.replicate_observations(cfg, [BURN])

    def test_observation_backlog_over_10000_is_chunked_for_every_signer(self):
        records = [self._burn(i) for i in range(10_001)]
        cfg = {
            "mode": "threshold_psbt",
            "threshold": 2,
            "signers": [
                {"id": "s1", "command": ["signer-one"]},
                {"id": "s2", "command": ["signer-two"]},
                {"id": "s3", "command": ["signer-three"]},
            ],
        }
        sizes = []

        def ok_run(cmd, **kwargs):
            request = json.loads(kwargs["input"])
            batch = request["records"]
            sizes.append(len(batch))
            sid = {"signer-one": "s1", "signer-two": "s2", "signer-three": "s3"}[cmd[0]]
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=json.dumps(
                    {
                        "signer_id": sid,
                        "observed": sorted(rd.redeem_id(x) for x in batch),
                    }
                ),
                stderr="",
            )

        with mock.patch.object(rd.subprocess, "run", side_effect=ok_run):
            ack = rd.replicate_observations(cfg, records)
        self.assertEqual(ack, ["s1", "s2", "s3"])
        self.assertGreater(len(sizes), 3)
        self.assertTrue(all(0 < n <= 500 for n in sizes))

    def test_fetch_walks_all_bounded_rpc_pages(self):
        source = [self._burn(i) for i in range(1_205)]

        class PagedFeed:
            def __init__(self):
                self.calls = 0

            def call(self, method, params=None):
                self.calls += 1
                self.assert_method = method
                cursor = (params or [""])[0]
                start = int(cursor[1:]) if cursor else 0
                page = source[start : start + 512]
                end = start + len(page)
                rows = [
                    {
                        "txid": x["burn_txid"],
                        "vout": x["opreturn_vout"],
                        "from": x["redeemer"],
                        "to": "",
                        "amount_sats": x["amount_sats"],
                        "block": x["burn_height"],
                        "block_hash": x["burn_block_hash"],
                        "memo": x["dest_btc_addr"],
                        "token": "btcVELD",
                        "is_mint": False,
                        "is_burn": False,
                        "is_redeem": True,
                    }
                    for x in page
                ]
                all_rows = [
                    {
                        "txid": x["burn_txid"],
                        "vout": x["opreturn_vout"],
                        "from": x["redeemer"],
                        "to": "",
                        "amount_sats": x["amount_sats"],
                        "block": x["burn_height"],
                        "block_hash": x["burn_block_hash"],
                        "memo": x["dest_btc_addr"],
                        "token": "btcVELD",
                        "is_mint": False,
                        "is_burn": False,
                        "is_redeem": True,
                    }
                    for x in source
                ]
                return {
                    "tip": 1000,
                    "tip_hash": "ab" * 32,
                    "final_height": 999,
                    "cursor": cursor,
                    "page_limit": 512,
                    "has_more": end < len(source),
                    "next_cursor": "c%d" % end,
                    "redeems": rows,
                    **rd.authority_for_rows(all_rows),
                }

        feed = PagedFeed()
        tip, final_height, found = rd.fetch_from_node(feed)
        self.assertEqual((tip, final_height), (1000, 999))
        self.assertEqual(len(found), len(source))
        self.assertEqual(feed.calls, 3)

    def test_fetch_restarts_on_same_height_tip_hash_change(self):
        source = [self._burn(i) for i in range(513)]

        class SameHeightReorgFeed:
            def __init__(self):
                self.calls = 0
                self.attempt = 0

            def call(self, method, params=None):
                self.calls += 1
                cursor = (params or [""])[0]
                if not cursor:
                    self.attempt += 1
                start = int(cursor[1:]) if cursor else 0
                page = source[start : start + 512]
                end = start + len(page)
                # First walk changes canonical identity without changing height;
                # the daemon must discard its partial rows and start over.
                tip_hash = "11" * 32 if self.attempt == 1 and not cursor else "22" * 32
                rows = [
                    {
                        "txid": x["burn_txid"],
                        "vout": x["opreturn_vout"],
                        "from": x["redeemer"],
                        "to": "",
                        "amount_sats": x["amount_sats"],
                        "block": x["burn_height"],
                        "block_hash": x["burn_block_hash"],
                        "memo": x["dest_btc_addr"],
                        "token": "btcVELD",
                        "is_mint": False,
                        "is_burn": False,
                        "is_redeem": True,
                    }
                    for x in page
                ]
                all_rows = [
                    {
                        "txid": x["burn_txid"],
                        "vout": x["opreturn_vout"],
                        "from": x["redeemer"],
                        "to": "",
                        "amount_sats": x["amount_sats"],
                        "block": x["burn_height"],
                        "block_hash": x["burn_block_hash"],
                        "memo": x["dest_btc_addr"],
                        "token": "btcVELD",
                        "is_mint": False,
                        "is_burn": False,
                        "is_redeem": True,
                    }
                    for x in source
                ]
                return {
                    "tip": 1000,
                    "tip_hash": tip_hash,
                    "final_height": 999,
                    "cursor": cursor,
                    "page_limit": 512,
                    "has_more": end < len(source),
                    "next_cursor": "c%d" % end,
                    "redeems": rows,
                    **rd.authority_for_rows(all_rows),
                }

        feed = SameHeightReorgFeed()
        tip, final_height, found = rd.fetch_from_node(feed)
        self.assertEqual((tip, final_height), (1000, 999))
        self.assertEqual(len(found), len(source))
        self.assertEqual(feed.attempt, 2)
        self.assertEqual(feed.calls, 4)

    def test_independent_signer_checks_exact_tx_then_commits_first_proposal(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            store.ingest([BURN], 200, 200)
            btc = SigningBtc()
            scripts = [btc.CUSTODY_SPK] + ["5120%064x" % i for i in range(1, 1000)]
            cfg = {
                "signer_id": "s1",
                "custody_descriptor": TEST_DESCRIPTOR,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_script_range": [0, 999],
                "custody_script_pubkeys": scripts,
                "btc_input_confirmations": 6,
                "max_payout_fee_sats": 2000,
            }
            base = {
                "redeem_id": rd.redeem_id(BURN),
                "burn_txid": BURN["burn_txid"],
                "opreturn_vout": BURN["opreturn_vout"],
                "amount_sats": BURN["amount_sats"],
                "burn_height": BURN["burn_height"],
                "burn_block_hash": BURN["burn_block_hash"],
                "dest_spk": BURN["dest_btc_addr"],
                "raw_tx_hex": "aa",
                "psbt": "psbt-a",
                "inputs": [
                    {"txid": btc.INPUT_TXID, "vout": 0, "value_sats": BURN["amount_sats"] + 1000}
                ],
                "fee_sats": 1000,
                "change_sats": 0,
                "change_spk": "",
                "marker_hex": rd.payout_marker(BURN).hex(),
            }
            answer = ps.sign(base, cfg, store, SigningVeld(), btc)
            self.assertEqual(answer, {"signer_id": "s1", "psbt": "partial-from-s1"})
            self.assertEqual(store.get_record(rd.redeem_id(BURN))["raw_tx_hex"], "aa")

            alternate = dict(base)
            alternate.update({"raw_tx_hex": "bb", "psbt": "psbt-b"})
            with self.assertRaises(SystemExit) as cm:
                ps.sign(alternate, cfg, store, SigningVeld(), btc)
            self.assertEqual(cm.exception.code, 2)
            store.close()

    def test_operational_manifest_and_public_boundary_scripts_are_enforced(self):
        descriptor = TEST_DESCRIPTOR
        descriptor_hash = hashlib.sha256(descriptor.encode()).hexdigest()
        scripts = [SigningBtc.CUSTODY_SPK] + ["5120%064x" % i for i in range(1, 11000)]
        document = {
            "version": 1,
            "descriptor": descriptor,
            "descriptor_sha256": descriptor_hash,
            "range": [0, 10999],
            "script_pubkeys": scripts,
        }
        manifest_hash = hashlib.sha256(
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        consensus = dict(document)
        consensus["range"] = [0, 999]
        consensus["script_pubkeys"] = scripts[:1000]
        consensus_hash = hashlib.sha256(
            (json.dumps(consensus, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        cfg = {
            "custody_descriptor": descriptor,
            "custody_descriptor_sha256": descriptor_hash,
            "custody_manifest_sha256": manifest_hash,
            "custody_consensus_manifest_sha256": consensus_hash,
            "custody_script_range": [0, 10999],
            "custody_script_pubkeys": scripts,
            "btc_input_confirmations": 6,
        }

        class BoundaryBtc:
            def __init__(self, script):
                self.script = script

            def call(self, method, *args):
                if method == "listdescriptors":
                    return {
                        "descriptors": [
                            {
                                "desc": descriptor,
                                "active": False,
                                "internal": False,
                                "range": [0, 10999],
                            }
                        ]
                    }
                if method == "gettxout":
                    return {
                        "value": "0.00001000",
                        "confirmations": 12,
                        "scriptPubKey": {"hex": self.script},
                    }
                raise AssertionError(method)

        with mock.patch.object(ps.custody_binding, "verify_core_derivation") as verify:
            policy = ps._verify_operational_custody_derivation(cfg, BoundaryBtc(scripts[1000]))
        self.assertEqual(policy["range"], [0, 10999])
        self.assertEqual(verify.call_args.args[1]["script_pubkeys"][10999], scripts[10999])

        decoded = {"vin": [{"txid": SigningBtc.INPUT_TXID, "vout": 0}]}
        for index in (1000, 10999):
            with self.subTest(index=index):
                resolved = ps._resolved_inputs(
                    BoundaryBtc(scripts[index]), decoded, cfg, CanonicalC1Veld(scripts[0])
                )
                self.assertEqual(resolved[0]["script_pubkey_hex"], scripts[index])
        self.assertTrue(ps._change_script_allowed(cfg, 1, scripts[999]))
        self.assertFalse(ps._change_script_allowed(cfg, 1, scripts[1000]))
        self.assertFalse(ps._change_script_allowed(cfg, 1, scripts[10999]))
        self.assertFalse(ps._change_script_allowed(cfg, 1, "5120" + "ff" * 32))

        tampered = dict(cfg)
        tampered["custody_manifest_sha256"] = "00" * 32
        with mock.patch.object(ps.custody_binding, "verify_core_derivation"):
            with self.assertRaises(SystemExit):
                ps._verify_operational_custody_derivation(tampered, BoundaryBtc(scripts[1000]))

    def test_public_c1_depth_100_refused_and_101_accepted(self):
        scripts = full_custody_scripts()
        policy = ps._custody_policy(public_custody_cfg(scripts))
        item = {"txid": SigningBtc.INPUT_TXID, "vout": 0, "script_pubkey_hex": scripts[1000]}
        with self.assertRaises(rd.PublicC1MintNotAccepted):
            rd.validate_payout_custody_inputs(
                CanonicalC1Veld(scripts[0], credit_depth=100), [item], policy
            )
        self.assertTrue(
            rd.validate_payout_custody_inputs(
                CanonicalC1Veld(scripts[0], credit_depth=101), [item], policy
            )
        )
        # The configured operator range remains eligible without any Veld
        # C1 query, even when no live Veld client is supplied.
        self.assertTrue(
            rd.validate_payout_custody_inputs(
                None, [{**item, "script_pubkey_hex": scripts[999]}], policy
            )
        )

    def test_public_c1_reorg_and_restart_are_rechecked(self):
        scripts = full_custody_scripts()
        cfg = public_custody_cfg(scripts)
        item = {"txid": SigningBtc.INPUT_TXID, "vout": 0, "script_pubkey_hex": scripts[1000]}
        veld = CanonicalC1Veld(scripts[0], credit_depth=101)
        self.assertTrue(rd.validate_payout_custody_inputs(veld, [item], ps._custody_policy(cfg)))
        # Model a process restart after the canonical credit carrier is reorged.
        # A freshly reconstructed policy has no positive-result cache to trust.
        veld.canonical = False
        with self.assertRaisesRegex(RuntimeError, "no longer canonical"):
            rd.validate_payout_custody_inputs(veld, [item], ps._custody_policy(dict(cfg)))

    def test_public_c1_race_before_key_use_is_refused(self):
        scripts = full_custody_scripts()
        cfg = public_custody_cfg(scripts)
        btc = SigningBtc()
        btc.CUSTODY_SPK = scripts[1000]
        veld = CanonicalC1Veld(scripts[0], credit_depth=101, race_after_first_status=True)
        request = {
            "redeem_id": rd.redeem_id(BURN),
            "burn_txid": BURN["burn_txid"],
            "opreturn_vout": BURN["opreturn_vout"],
            "amount_sats": BURN["amount_sats"],
            "burn_height": BURN["burn_height"],
            "burn_block_hash": BURN["burn_block_hash"],
            "dest_spk": BURN["dest_btc_addr"],
            "raw_tx_hex": "aa",
            "psbt": "psbt-a",
            "inputs": [
                {"txid": btc.INPUT_TXID, "vout": 0, "value_sats": BURN["amount_sats"] + 1000}
            ],
            "fee_sats": 1000,
            "change_sats": 0,
            "change_spk": "",
            "marker_hex": rd.payout_marker(BURN).hex(),
        }
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            store.ingest([BURN], 300, 300)
            with self.assertRaises(SystemExit) as cm:
                ps.sign(request, cfg, store, veld, btc)
            self.assertEqual(cm.exception.code, 2)
            self.assertEqual(veld.status_calls, 2)
            self.assertEqual(btc.wallet_sign_calls, 0)
            self.assertIsNone(store.get_record(rd.redeem_id(BURN))["raw_tx_hex"])
            store.close()

    def test_public_change_is_refused(self):
        scripts = full_custody_scripts()
        cfg = public_custody_cfg(scripts)
        self.assertTrue(ps._change_script_allowed(cfg, 1, scripts[999]))
        self.assertFalse(ps._change_script_allowed(cfg, 1, scripts[1000]))

    def test_builder_skips_pending_public_input_and_uses_deep_c1_mint(self):
        scripts = full_custody_scripts()
        policy = ps._custody_policy(public_custody_cfg(scripts))
        operator_txid = "f0" * 32
        pending_txid = "01" * 32
        accepted_txid = "02" * 32

        class BuilderVeld(CanonicalC1Veld):
            def _status(self, outpoint):
                old = self.phase
                if outpoint == pending_txid + ":0":
                    self.phase = "C1_FUND"
                try:
                    return super()._status(outpoint)
                finally:
                    self.phase = old

        class BuilderBtc:
            def __init__(self):
                self.inputs = None
                self.outputs = None

            def call(self, method, *args):
                if method == "decodescript":
                    return {"address": "dest-address"}
                if method == "getaddressinfo":
                    return {"scriptPubKey": scripts[999]}
                if method == "listunspent":
                    return [
                        {
                            "txid": pending_txid,
                            "vout": 0,
                            "amount": "0.00050000",
                            "confirmations": 12,
                            "spendable": True,
                            "solvable": True,
                            "scriptPubKey": scripts[1000],
                        },
                        {
                            "txid": accepted_txid,
                            "vout": 0,
                            "amount": "0.00050000",
                            "confirmations": 12,
                            "spendable": True,
                            "solvable": True,
                            "scriptPubKey": scripts[1001],
                        },
                        {
                            "txid": operator_txid,
                            "vout": 0,
                            "amount": "0.00050000",
                            "confirmations": 12,
                            "spendable": True,
                            "solvable": True,
                            "scriptPubKey": scripts[999],
                        },
                    ]
                if method == "createrawtransaction":
                    self.inputs = json.loads(args[0])
                    self.outputs = json.loads(args[1])
                    return "aa"
                if method == "decoderawtransaction":
                    outputs = []
                    for destination, value in self.outputs.items():
                        if destination == "data":
                            outputs.append(
                                {
                                    "value": "0.00000000",
                                    "scriptPubKey": {"hex": rd.payout_marker_script(BURN)},
                                }
                            )
                        else:
                            outputs.append(
                                {
                                    "value": value,
                                    "scriptPubKey": {
                                        "hex": (
                                            BURN["dest_btc_addr"]
                                            if destination == "dest-address"
                                            else scripts[999]
                                        )
                                    },
                                }
                            )
                    return {
                        "txid": "ee" * 32,
                        "version": 2,
                        "locktime": 0,
                        "vin": [
                            {**item, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}}
                            for item in self.inputs
                        ],
                        "vout": outputs,
                    }
                raise AssertionError((method, args))

        btc = BuilderBtc()
        raw, selected, _fee, _change, change_spk = rd.build_payout(
            btc,
            BURN,
            "change",
            {
                "btc_input_confirmations": 1,
                "custody_input_vbytes": 68,
                "feerate_sat_vb": 1,
            },
            veld=BuilderVeld(scripts[0]),
            custody_policy=policy,
        )
        self.assertEqual(raw, "aa")
        self.assertEqual(change_spk, scripts[999])
        self.assertEqual(
            [(x["txid"], x["vout"]) for x in selected], [(operator_txid, 0), (accepted_txid, 0)]
        )

    def test_coordinator_rechecks_public_c1_after_quorum_before_broadcast(self):
        scripts = full_custody_scripts()
        policy = ps._custody_policy(public_custody_cfg(scripts))
        selected = [
            {
                "txid": SigningBtc.INPUT_TXID,
                "vout": 0,
                "value_sats": BURN["amount_sats"] + 1000,
                "script_pubkey_hex": scripts[1000],
            }
        ]
        record = {**BURN, "rid": rd.redeem_id(BURN), "status": "observed"}
        veld = CanonicalC1Veld(scripts[0], credit_depth=101)

        class Store:
            def __init__(self):
                self.transitions = []

            def open_records(self):
                return [record]

            def transition(self, *args, **kwargs):
                self.transitions.append((args, kwargs))

        store = Store()
        coordinator = rd.RedeemCoordinator(
            {"change_addr": "change", "payout_signing": {"mode": "threshold_psbt"}},
            store,
            object(),
            veld,
        )
        coordinator.reconcile_bitcoin_authority = mock.Mock()

        def quorum_then_reorg(*_args, **_kwargs):
            veld.canonical = False
            return "bb", ["s1", "s2", "s3"]

        with (
            mock.patch.object(rd, "load_payout_custody_policy", return_value=policy),
            mock.patch.object(rd, "find_existing_payout", return_value=None),
            mock.patch.object(rd, "verify_burn_canonical", return_value=(True, "canonical")),
            mock.patch.object(
                rd, "build_payout", return_value=("aa", selected, 1000, 0, scripts[999])
            ),
            mock.patch.object(rd, "sign_payout", side_effect=quorum_then_reorg),
            mock.patch.object(rd, "validate_payout_tx"),
        ):
            with self.assertRaisesRegex(RuntimeError, "no longer canonical"):
                coordinator.process(300, 300)
        self.assertEqual(store.transitions, [])

    def test_signer_refuses_same_custody_input_across_different_redemptions(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            second = dict(BURN)
            second.update({"burn_txid": "9f" * 32, "opreturn_vout": 2})
            store.ingest([BURN, second], 200, 200)
            shared = [(SigningBtc.INPUT_TXID, 0)]
            store.commit_signing_proposal(rd.redeem_id(BURN), "aa", shared)
            with self.assertRaisesRegex(RuntimeError, "another redemption"):
                store.commit_signing_proposal(rd.redeem_id(second), "bb", shared)
            self.assertIsNone(store.get_record(rd.redeem_id(second))["raw_tx_hex"])
            store.close()

    def test_signer_refuses_weak_sighash_and_preloaded_signature_psbts(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            store.ingest([BURN], 200, 200)
            btc = SigningBtc()
            scripts = [btc.CUSTODY_SPK] + ["5120%064x" % i for i in range(1, 1000)]
            cfg = {
                "signer_id": "s1",
                "custody_descriptor": TEST_DESCRIPTOR,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_script_range": [0, 999],
                "custody_script_pubkeys": scripts,
                "btc_input_confirmations": 6,
                "max_payout_fee_sats": 2000,
            }
            request = {
                "redeem_id": rd.redeem_id(BURN),
                "burn_txid": BURN["burn_txid"],
                "opreturn_vout": BURN["opreturn_vout"],
                "amount_sats": BURN["amount_sats"],
                "burn_height": BURN["burn_height"],
                "burn_block_hash": BURN["burn_block_hash"],
                "dest_spk": BURN["dest_btc_addr"],
                "raw_tx_hex": "aa",
                "psbt": "psbt-a",
                "inputs": [
                    {"txid": btc.INPUT_TXID, "vout": 0, "value_sats": BURN["amount_sats"] + 1000}
                ],
                "fee_sats": 1000,
                "change_sats": 0,
                "change_spk": "",
                "marker_hex": rd.payout_marker(BURN).hex(),
            }
            for sighash in ("NONE", "SINGLE", "ALL|ANYONECANPAY", "SINGLE|ANYONECANPAY", 1):
                with self.subTest(sighash=sighash):
                    btc.psbt_sighash = sighash
                    with self.assertRaises(SystemExit) as cm:
                        ps.sign(request, cfg, store, SigningVeld(), btc)
                    self.assertEqual(cm.exception.code, 2)
            btc.psbt_sighash = "ALL"
            for field in ("partial_signatures", "taproot_key_path_sig", "taproot_script_path_sigs"):
                with self.subTest(field=field):
                    btc.psbt_extra = {field: {"attacker": "00"}}
                    with self.assertRaises(SystemExit) as cm:
                        ps.sign(request, cfg, store, SigningVeld(), btc)
                    self.assertEqual(cm.exception.code, 2)
            self.assertIsNone(store.get_record(rd.redeem_id(BURN))["raw_tx_hex"])
            store.close()

    def test_signer_refuses_chain_movement_during_burn_finality_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            store.ingest([BURN], 200, 200)
            btc = SigningBtc()
            scripts = [btc.CUSTODY_SPK] + ["5120%064x" % i for i in range(1, 1000)]
            cfg = {
                "signer_id": "s1",
                "custody_descriptor": TEST_DESCRIPTOR,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_script_range": [0, 999],
                "custody_script_pubkeys": scripts,
                "btc_input_confirmations": 6,
                "max_payout_fee_sats": 2000,
            }
            request = {
                "redeem_id": rd.redeem_id(BURN),
                "burn_txid": BURN["burn_txid"],
                "opreturn_vout": BURN["opreturn_vout"],
                "amount_sats": BURN["amount_sats"],
                "burn_height": BURN["burn_height"],
                "burn_block_hash": BURN["burn_block_hash"],
                "dest_spk": BURN["dest_btc_addr"],
                "raw_tx_hex": "aa",
                "psbt": "psbt-a",
                "inputs": [
                    {"txid": btc.INPUT_TXID, "vout": 0, "value_sats": BURN["amount_sats"] + 1000}
                ],
                "fee_sats": 1000,
                "change_sats": 0,
                "change_spk": "",
                "marker_hex": rd.payout_marker(BURN).hex(),
            }
            with self.assertRaises(SystemExit) as cm:
                ps.sign(request, cfg, store, RacingSigningVeld(), btc)
            self.assertEqual(cm.exception.code, 2)
            self.assertIsNone(store.get_record(rd.redeem_id(BURN))["raw_tx_hex"])
            store.close()

    def test_signer_refuses_nonfinal_or_prepopulated_raw_payout(self):
        with tempfile.TemporaryDirectory() as td:
            store = rd.ObligationStore(str(Path(td) / "signer.sqlite3"))
            store.ingest([BURN], 200, 200)
            btc = SigningBtc()
            scripts = [btc.CUSTODY_SPK] + ["5120%064x" % i for i in range(1, 1000)]
            cfg = {
                "signer_id": "s1",
                "custody_descriptor": TEST_DESCRIPTOR,
                "custody_descriptor_sha256": "ab" * 32,
                "custody_manifest_sha256": "cd" * 32,
                "custody_script_range": [0, 999],
                "custody_script_pubkeys": scripts,
                "btc_input_confirmations": 6,
                "max_payout_fee_sats": 2000,
            }
            request = {
                "redeem_id": rd.redeem_id(BURN),
                "burn_txid": BURN["burn_txid"],
                "opreturn_vout": BURN["opreturn_vout"],
                "amount_sats": BURN["amount_sats"],
                "burn_height": BURN["burn_height"],
                "burn_block_hash": BURN["burn_block_hash"],
                "dest_spk": BURN["dest_btc_addr"],
                "raw_tx_hex": "aa",
                "psbt": "psbt-a",
                "inputs": [
                    {"txid": btc.INPUT_TXID, "vout": 0, "value_sats": BURN["amount_sats"] + 1000}
                ],
                "fee_sats": 1000,
                "change_sats": 0,
                "change_spk": "",
                "marker_hex": rd.payout_marker(BURN).hex(),
            }
            mutations = (
                ("tx_version", 1),
                ("tx_locktime", 500_000_000),
                ("tx_sequence", 0xFFFFFFFE),
                ("tx_script_sig", "01"),
                ("tx_witness", ["00"]),
            )
            for field, value in mutations:
                with self.subTest(field=field):
                    candidate = SigningBtc()
                    setattr(candidate, field, value)
                    with self.assertRaises((RuntimeError, SystemExit)):
                        ps.sign(request, cfg, store, SigningVeld(), candidate)
            self.assertIsNone(store.get_record(rd.redeem_id(BURN))["raw_tx_hex"])
            store.close()

    def test_legacy_proposal_is_backfilled_before_new_signing(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "signer.sqlite3")
            store = rd.ObligationStore(path)
            store.ingest([BURN], 200, 200)
            rid = rd.redeem_id(BURN)
            # Model the pre-upgrade schema state: the obligation contains a raw
            # lock but the new proposal/input tables have no row yet.
            store.db.execute(
                "UPDATE obligations SET status='broadcasting',raw_tx_hex='aa' WHERE rid=?", (rid,)
            )
            ps.backfill_legacy_input_commitments(store, SigningBtc())
            rows = store.db.execute(
                "SELECT txid,vout,rid FROM signing_input_commitments"
            ).fetchall()
            self.assertEqual(rows, [(SigningBtc.INPUT_TXID, 0, rid)])
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
