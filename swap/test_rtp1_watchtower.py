import copy
import unittest
from unittest import mock

import rtp1_watchtower as observer
from test_rtp1_service import fixture


class Rtp1WatchtowerTests(unittest.TestCase):
    def test_core_keypool_extension_preserves_pinned_authority(self):
        binding = {"descriptor": "pinned", "range": [0, 999]}
        for end in (999, 1000, 1000000):
            observer.verify_wallet_descriptor({"descriptors": [{"desc": "pinned", "active": False,
                "range": [0, end]}]}, binding)

    def test_disposable_observer_may_require_more_burial_but_never_less(self):
        instance = observer.Rtp1Watchtower.__new__(observer.Rtp1Watchtower)
        instance.rtp1, instance.production_binding, instance.k_confs = self.config, {}, 144
        instance.veld = mock.Mock()
        with mock.patch.object(observer, "verify_expected_chain"), mock.patch.object(observer.custody, "verify_peg_identity"):
            for depth in (3, 144):
                instance.veld.rpc.return_value = {"issuer": self.config["issuer"], "spv_k_btc": depth}
                instance._verify_production_veld_identity()
            for depth in (True, 0, None, 145):
                instance.veld.rpc.return_value = {"issuer": self.config["issuer"], "spv_k_btc": depth}
                with self.assertRaises(ValueError): instance._verify_production_veld_identity()

    def test_descriptor_coverage_and_role_must_be_exact(self):
        binding = {"descriptor": "pinned", "range": [0, 999]}
        good = {"desc": "pinned", "active": False, "range": [0, 1000]}
        for change in ({"desc": "other"}, {"active": True}, {"internal": True},
                {"range": [0, 998]}, {"range": [1, 1000]}, {"range": [False, 1000]},
                {"range": [0, 1000001]}, {"range": None}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                observer.verify_wallet_descriptor({"descriptors": [dict(good, **change)]}, binding)
        for entries in ([], [good, good], None, [None]):
            with self.assertRaises(ValueError):
                observer.verify_wallet_descriptor({"descriptors": entries}, binding)

    def setUp(self):
        self.config = fixture()[0]
        self.scripts = [self.config["custody_script_hex"]] + ["5120" + format(i, "064x") for i in range(999)]
        self.native = {"supply_sats": 100000, "tip": 3000, "tip_hash": "aa" * 32}
        self.peg = dict(self.native, reserve_semantics="rolling-outpoint-v1", reserve_status="ACTIVE",
            reserve_accounting_holds=True, open_redemption_principal_sats=20000, reserve_value_sats=125000,
            reserve_surplus_sats=5000, issuer=self.config["issuer"], token_id="btcVELD",
            custody_descriptor_sha256=self.config["custody_descriptor_sha256"], custody_manifest_sha256=self.config["custody_manifest_sha256"])
        self.frame = {"chain": "regtest", "initialblockdownload": False, "blocks": 500, "headers": 500, "bestblockhash": "bb" * 32}
        self.rows = [{"txid": "cc" * 32, "vout": 0, "confirmations": 144,
            "scriptPubKey": self.scripts[0], "amount": 0.002}]
        self.coin = {"bestblock": "bb" * 32, "confirmations": 144, "scriptPubKey": {"hex": self.scripts[0]}, "value": 0.002}
        self.veld_reads, self.btc_reads = [], []

    def veld(self, method, params):
        self.veld_reads.append(method)
        return copy.deepcopy({"getbtcveldsupply": self.native, "getpeginfo": self.peg, "getblockhash": self.native["tip_hash"]}[method])

    def bitcoin(self, method, params):
        self.btc_reads.append((method, params))
        if method == "getblockhash": return self.config["bitcoin_genesis"] if params == [0] else self.frame["bestblockhash"]
        return copy.deepcopy({"getblockchaininfo": self.frame, "listunspent": self.rows, "gettxout": self.coin}[method])

    def read(self, **changes):
        with mock.patch.object(observer, "verify_expected_chain") as pinned:
            result = observer.read_snapshot(dict(self.config, **changes), self.veld, self.bitcoin, self.scripts)
            pinned.assert_called_once_with(self.veld, self.config["expected_chain"])
        return result

    def test_unsettled_redemptions_remain_liabilities(self):
        view = self.read()
        self.assertEqual(view["custody_sats"], 200000)
        self.assertEqual(view["backing_liability_sats"], 120000)
        self.assertIn(("gettxout", ["cc" * 32, 0, True]), self.btc_reads)

    def test_duplicate_output_cannot_manufacture_headroom(self):
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaises(ValueError): self.read()

    def test_unrelated_script_refuses_before_coin_lookup(self):
        self.rows[0]["scriptPubKey"] = "5120" + "fe" * 32
        with self.assertRaises(ValueError): self.read()
        self.assertNotIn("gettxout", [method for method, _ in self.btc_reads])

    def test_mempool_spent_coin_cannot_count_as_backing(self):
        self.coin = None
        with self.assertRaises(ValueError): self.read()

    def test_coin_mismatch_and_malformed_values_refuse(self):
        for change in ({"value": True}, {"value": 0.002000001}, {"value": 0.003},
                {"confirmations": True}, {"bestblock": "dd" * 32}):
            old = copy.deepcopy(self.coin)
            self.coin.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.read()
            self.coin = old

    def test_frozen_or_incoherent_native_reserve_refuses(self):
        for field, value in (("reserve_status", "FROZEN"), ("reserve_accounting_holds", 1),
                ("reserve_value_sats", 124999), ("open_redemption_principal_sats", True),
                ("custody_manifest_sha256", "dd" * 32), ("tip", 2999)):
            old = copy.deepcopy(self.peg)
            self.peg[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.read()
            self.peg = old

    def test_inventory_bound_precedes_per_coin_work(self):
        self.rows *= observer.MAX_CUSTODY_UTXOS + 1
        with self.assertRaises(ValueError): self.read()
        self.assertNotIn("gettxout", [method for method, _ in self.btc_reads])

    def test_bitcoin_frame_change_refuses_snapshot(self):
        original = self.bitcoin
        def moving(method, params):
            result = original(method, params)
            if method == "gettxout": self.frame["bestblockhash"] = "dd" * 32
            return result
        self.bitcoin = moving
        with self.assertRaises(ValueError): self.read()

    def test_native_frame_change_refuses_snapshot(self):
        original = self.bitcoin
        def moving(method, params):
            result = original(method, params)
            if method == "gettxout": self.native["tip"] += 1
            return result
        self.bitcoin = moving
        with self.assertRaises(ValueError): self.read()

    def test_live_profile_never_activates_this_adapter(self):
        with self.assertRaises(ValueError):
            self.read(expected_chain=dict(self.config["expected_chain"], external_value=True))
        with self.assertRaises(ValueError): self.read(bitcoin_network="main")
        self.assertEqual(self.btc_reads, [])


if __name__ == "__main__":
    unittest.main()
