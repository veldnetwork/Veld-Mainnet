#!/usr/bin/env python3
"""C-05/N-02/H-06 focused redemption durability regressions."""
import tempfile
import unittest
from pathlib import Path

from swap import veld_redeemd as rd


BURN = {
    "burn_txid": "ab" * 32,
    "opreturn_vout": 2,
    "redeemer": "V" + "1" * 33,
    "amount_sats": 125_000,
    "burn_height": 100,
    "burn_block_hash": "cd" * 32,
    "dest_btc_addr": "0014" + "22" * 20,
}


class MarkerBtc:
    def __init__(self, burn=BURN, confirmations=3, wrong_amount=False,
                 abandoned=False, no_marker=False, outgoing=True):
        self.burn = dict(burn)
        self.txid = "ef" * 32
        self.confirmations = confirmations
        self.wrong_amount = wrong_amount
        self.abandoned = abandoned
        self.no_marker = no_marker
        self.outgoing = outgoing
        self.broadcasts = []

    def call(self, method, *args):
        if method == "listsinceblock":
            return {"transactions": [{"txid": self.txid}], "removed": []}
        if method == "gettransaction":
            return {"hex": "deadbeef", "confirmations": self.confirmations,
                    "abandoned": self.abandoned, "walletconflicts": [],
                    "details": [{"category": "send" if self.outgoing else "receive"}]}
        if method == "decoderawtransaction":
            outs = [{"value": rd.btc_str(self.burn["amount_sats"] + (1 if self.wrong_amount else 0)),
                     "scriptPubKey": {"hex": self.burn["dest_btc_addr"]}}]
            if not self.no_marker:
                outs.append({"value": "0.00000000",
                             "scriptPubKey": {"hex": rd.payout_marker_script(self.burn)}})
            return {"vin": [], "vout": outs}
        if method == "sendrawtransaction":
            self.broadcasts.append(args[0]); return self.txid
        raise AssertionError("unexpected Bitcoin RPC %s" % method)


class FakeVeld:
    def __init__(self, canonical=True):
        self.canonical = canonical

    def call(self, method, params=None):
        if method == "getblockhash":
            return BURN["burn_block_hash"] if self.canonical else "00" * 32
        if method == "gettransaction":
            return {"txid": BURN["burn_txid"],
                    "block_hash": BURN["burn_block_hash"]}
        raise AssertionError("unexpected Veld RPC %s" % method)


class AgedOutRedeemFeed:
    """RPC shape emitted by the paginated derived obligation index."""
    def call(self, method, params=None):
        if method != "getbtcveldredeems":
            raise AssertionError("unexpected Veld RPC %s" % method)
        cursor = (params or [""])[0]
        rows = [{
            "txid": BURN["burn_txid"], "vout": BURN["opreturn_vout"],
            "from": BURN["redeemer"], "to": "",
            "amount_sats": BURN["amount_sats"],
            "block": BURN["burn_height"], "memo": BURN["dest_btc_addr"],
            "token": "btcVELD", "is_mint": False, "is_burn": False,
            "is_redeem": True, "block_hash": BURN["burn_block_hash"],
        }]
        return {"tip": 2201, "tip_hash": "ee" * 32,
                "final_height": 2201, "cursor": cursor,
                "next_cursor": cursor, "has_more": False,
                "page_limit": 512, "redeems": rows,
                **rd.authority_for_rows(rows)}


class RedemptionDurabilityTests(unittest.TestCase):
    def make_store(self, root, name="authority.sqlite3"):
        return rd.ObligationStore(str(Path(root) / name))

    def test_observed_burn_cannot_age_out_of_durable_queue(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td)
            s.ingest([BURN], tip=100, final_height=100)
            # Simulates a later node feed whose bounded history no longer contains
            # the immature burn after thousands of unrelated token operations.
            s.ingest([], tip=300, final_height=300)
            rows = s.open_records()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["burn_txid"], BURN["burn_txid"])
            self.assertEqual(rows[0]["status"], "observed")
            s.close()

    def test_offline_observer_discovers_aged_out_burn_via_paginated_rpc(self):
        # Models first startup after an outage longer than the old 2,000-record
        # UI-history window.  The derived paginated obligation RPC still returns the burn,
        # and the coordinator commits it before doing any maturity/payout work.
        tip, final_height, pending = rd.fetch_from_node(AgedOutRedeemFeed())
        self.assertEqual((tip, final_height), (2201, 2201))
        self.assertEqual(pending, [BURN])
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td)
            s.ingest(pending, tip, final_height)
            self.assertEqual(s.get_record(rd.redeem_id(BURN))["status"], "observed")
            s.close()

    def test_coordinator_rejects_a_whole_deleted_index_row(self):
        first = {
            "txid": BURN["burn_txid"], "vout": BURN["opreturn_vout"],
            "from": BURN["redeemer"], "to": "",
            "amount_sats": BURN["amount_sats"],
            "block": BURN["burn_height"], "memo": BURN["dest_btc_addr"],
            "token": "btcVELD", "is_mint": False, "is_burn": False,
            "is_redeem": True, "block_hash": BURN["burn_block_hash"],
        }
        deleted = dict(first)
        deleted["txid"] = "ac" * 32
        authority = rd.authority_for_rows([first, deleted])

        class MissingRowFeed:
            def call(self, method, params=None):
                cursor = (params or [""])[0]
                return {
                    "tip": 2201, "tip_hash": "ee" * 32,
                    "final_height": 2201, "cursor": cursor,
                    "next_cursor": cursor, "has_more": False,
                    "page_limit": 512, "redeems": [first],
                    **authority,
                }

        with self.assertRaisesRegex(
                RuntimeError, "completeness commitment mismatch"):
            rd.fetch_from_node(MissingRowFeed())

    def test_restart_and_concurrent_ingest_are_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            s1 = self.make_store(td)
            s1.ingest([BURN], 100, 100)
            s2 = self.make_store(td)
            s2.ingest([BURN], 101, 101)
            self.assertEqual(len(s1.all_records()), 1)
            self.assertEqual(len(s2.all_records()), 1)
            s1.close(); s2.close()

    def test_split_brain_signers_commit_first_transaction_only(self):
        with tempfile.TemporaryDirectory() as td:
            s1 = self.make_store(td); s1.ingest([BURN], 300, 300)
            s2 = self.make_store(td)
            rid = rd.redeem_id(BURN)
            inputs = [("11" * 32, 0)]
            s1.commit_signing_proposal(rid, "aa00", inputs)
            # A second process sharing this signer's authority may retry the exact
            # proposal, but cannot overwrite it with alternate reserve inputs.
            s2.commit_signing_proposal(rid, "aa00", inputs)
            with self.assertRaisesRegex(RuntimeError, "different payout"):
                s2.commit_signing_proposal(rid, "bb00", [("22" * 32, 1)])
            self.assertEqual(s1.get_record(rid)["raw_tx_hex"], "aa00")
            s1.close(); s2.close()

    def test_same_outpoint_with_changed_obligation_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 100, 100)
            changed = dict(BURN); changed["amount_sats"] += 1
            with self.assertRaisesRegex(RuntimeError, "changed redemption identity"):
                s.ingest([changed], 101, 101)
            self.assertEqual(s.all_records()[0]["amount_sats"], BURN["amount_sats"])
            s.close()

    def test_whole_local_state_loss_recovers_paid_truth_from_bitcoin_marker(self):
        # No fulfilled JSON, intent log, or prior DB record is needed for the
        # idempotency decision: re-observe the burn, then recover from Bitcoin.
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            btc = MarkerBtc(confirmations=6)
            c = rd.RedeemCoordinator({"change_addr": "change", "payout_signing": {}},
                                     s, btc, FakeVeld())
            c.reconcile_bitcoin_authority()
            row = s.all_records()[0]
            self.assertEqual(row["status"], "paid")
            self.assertEqual(row["payout_txid"], btc.txid)
            s.close()

    def test_fresh_authority_refuses_legacy_mature_unmarked_burn(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            with self.assertRaisesRegex(RuntimeError, "mature unmarked burn"):
                rd.guard_fresh_authority(s, MarkerBtc(no_marker=True), 300)
            self.assertEqual(s.get_record(rd.redeem_id(BURN))["status"], "observed")
            s.close()

    def test_exact_reorg_depth_is_not_payout_final(self):
        self.assertFalse(rd.clears_veld_reorg_horizon(
            BURN["burn_height"] + rd.MAX_REORG_DEPTH,
            BURN["burn_height"]))
        self.assertTrue(rd.clears_veld_reorg_horizon(
            BURN["burn_height"] + rd.MAX_REORG_DEPTH + 1,
            BURN["burn_height"]))

    def test_runtime_consensus_depth_must_match_payout_policy(self):
        class ChainInfo:
            def __init__(self, depth):
                self.depth = depth

            def call(self, method, params=None):
                if method != "getblockchaininfo":
                    raise AssertionError(method)
                return {"max_reorg_depth": self.depth}

        self.assertEqual(rd.require_consensus_reorg_depth(
            ChainInfo(rd.MAX_REORG_DEPTH)), rd.MAX_REORG_DEPTH)
        with self.assertRaisesRegex(RuntimeError, "differs from connected consensus"):
            rd.require_consensus_reorg_depth(
                ChainInfo(rd.MAX_REORG_DEPTH + 1))

    def test_fresh_authority_accepts_mature_burn_with_bitcoin_marker(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            rd.guard_fresh_authority(s, MarkerBtc(confirmations=2), 300)
            s.close()

    def test_stale_restore_cannot_demote_paid_marker_or_repay(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            s.transition(rd.redeem_id(BURN), "observed", note="simulated stale restore")
            btc = MarkerBtc(confirmations=2)
            rd.RedeemCoordinator({"change_addr": "change", "payout_signing": {}},
                                 s, btc, FakeVeld()).reconcile_bitcoin_authority()
            self.assertEqual(s.all_records()[0]["status"], "paid")
            self.assertEqual(btc.broadcasts, [])
            s.close()

    def test_bitcoin_reorg_rebroadcasts_exact_same_transaction(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            rid = rd.redeem_id(BURN)
            s.transition(rid, "paid", payout_txid="ef" * 32, raw_tx_hex="deadbeef")
            btc = MarkerBtc(confirmations=0)
            rd.RedeemCoordinator({"change_addr": "change", "payout_signing": {}},
                                 s, btc, FakeVeld()).reconcile_bitcoin_authority()
            self.assertEqual(btc.broadcasts, ["deadbeef"])
            self.assertEqual(s.all_records()[0]["status"], "paid")
            s.close()

    def test_wrong_marker_payment_is_a_hard_failure(self):
        with self.assertRaisesRegex(RuntimeError, "wrong amount/destination"):
            rd.find_existing_payout(MarkerBtc(wrong_amount=True), BURN)

    def test_incoming_forged_marker_is_not_payment_authority(self):
        # Anyone can publish the marker bytes and a dust output to the custody
        # wallet.  Only an outgoing, custody-input wallet transaction can satisfy
        # the independent Bitcoin payment authority.
        self.assertIsNone(rd.find_existing_payout(MarkerBtc(outgoing=False), BURN))

    def test_conflicted_marker_holds_instead_of_switching_inputs(self):
        with self.assertRaisesRegex(RuntimeError, "manual hold"):
            rd.find_existing_payout(MarkerBtc(confirmations=-1), BURN)

    def test_pre_payout_veld_reorg_is_rejected(self):
        ok, why = rd.verify_burn_canonical(FakeVeld(canonical=False), BURN)
        self.assertFalse(ok)
        self.assertIn("no longer canonical", why)

    def test_paid_veld_burn_reorg_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.make_store(td); s.ingest([BURN], 300, 300)
            s.transition(rd.redeem_id(BURN), "paid", payout_txid="ef" * 32)
            c = rd.RedeemCoordinator({"change_addr": "change", "payout_signing": {}},
                                     s, MarkerBtc(confirmations=5), FakeVeld(canonical=False))
            with self.assertRaisesRegex(RuntimeError, "lost canonical finality"):
                c.reconcile_bitcoin_authority()
            s.close()

    def test_single_wallet_requires_explicit_development_override(self):
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            rd.sign_payout(MarkerBtc(), "00", {}, {"mode": "single_wallet_dev"})

    def test_threshold_requires_independent_quorum(self):
        with self.assertRaisesRegex(RuntimeError, "exactly 3-of-5"):
            rd.sign_payout(MarkerBtc(), "00", {},
                           {"mode": "threshold_psbt", "threshold": 1,
                            "signers": [{"id": "a", "command": ["false"]}]})
        with self.assertRaisesRegex(RuntimeError, "exactly 3-of-5"):
            rd.sign_payout(MarkerBtc(), "00", {},
                           {"mode": "threshold_psbt", "threshold": 2,
                            "signers": [{"id": x, "command": ["false", x]}
                                        for x in "abcd"]})

    def test_marker_is_full_outpoint_and_standard_size(self):
        marker = rd.payout_marker(BURN)
        self.assertEqual(len(marker), 41)
        self.assertEqual(marker[:5], rd.PAYOUT_MARKER_MAGIC)
        self.assertEqual(marker[-4:], (2).to_bytes(4, "big"))
        self.assertEqual(len(rd.redeem_id(BURN)), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
