import copy
from decimal import Decimal
import unittest
from unittest import mock

import rtp1_backing_evidence as evidence


class BackingEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            "version": 1,
            "operation": "OPEN",
            "network_binding": "11" * 32,
            "prior_commitment": "22" * 32,
            "prior_transition_count": 0,
            "bitcoin_txid": "33" * 32,
            "bitcoin_block": "44" * 32,
            "reserve_vout": 0,
            "reserve_value_sats": 12345678,
            "deposit_outpoint": "33" * 32 + ":0",
            "exact_commitment": "55" * 32,
            "sats": 12345678,
            "issuer": "V" + "1" * 30,
            "recipient": "V" + "2" * 30,
            "custody_script_hex": "5120" + "66" * 32,
            "direct_parent_txids": ["77" * 32],
        }
        self.policy = {
            "expected_network": "regtest",
            "expected_genesis": "88" * 32,
            "custody_script_hex": self.facts["custody_script_hex"],
            "min_confirmations": 144,
        }
        self.info = {
            "chain": "regtest",
            "initialblockdownload": False,
            "blocks": 200,
            "headers": 200,
            "bestblockhash": "99" * 32,
        }
        self.header = {"hash": self.facts["bitcoin_block"], "height": 50, "confirmations": 151}
        self.tx = {
            "txid": self.facts["bitcoin_txid"],
            "blockhash": self.facts["bitcoin_block"],
            "in_active_chain": True,
            "vin": [{"txid": "77" * 32, "vout": 0}],
            "vout": [
                {
                    "n": 0,
                    "value": 0.12345678,
                    "scriptPubKey": {"hex": self.facts["custody_script_hex"]},
                }
            ],
        }
        self.unspent = {
            "bestblock": self.info["bestblockhash"],
            "confirmations": 151,
            "coinbase": False,
            "value": 0.12345678,
            "scriptPubKey": {"hex": self.facts["custody_script_hex"]},
        }
        self.calls = []
        self.after = None

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method == "getblockhash":
            return {
                0: self.policy["expected_genesis"],
                50: self.facts["bitcoin_block"],
                200: self.info["bestblockhash"],
            }.get(params[0])
        if method == "getblockchaininfo":
            if self.after and sum(m == method for m, p in self.calls) > 1:
                return copy.deepcopy(self.after)
            return copy.deepcopy(self.info)
        if method == "getblockheader":
            return copy.deepcopy(self.header)
        if method == "getrawtransaction":
            return copy.deepcopy(self.tx)
        if method == "gettxout":
            return copy.deepcopy(self.unspent)
        raise AssertionError(method)

    def verify(self):
        return evidence.verify_bitcoin_backing(self.rpc, self.facts, **self.policy)

    def test_exact_canonical_unspent_successor(self):
        result = self.verify()
        self.assertEqual(result["confirmations"], 151)
        self.assertEqual(result["reserve_value_sats"], 12345678)
        self.assertIn(("gettxout", ["33" * 32, 0, True]), self.calls)
        self.assertEqual(self.calls.count(("getblockhash", [0])), 2)

    def test_deposit_checks_successor_not_consumed_pending_output(self):
        self.facts.update(
            operation="DEPOSIT",
            prior_transition_count=1,
            deposit_outpoint="aa" * 32 + ":1",
            direct_parent_txids=["77" * 32, "aa" * 32],
        )
        self.tx["vin"].append({"txid": "aa" * 32, "vout": 1})
        self.verify()
        self.assertEqual([p for m, p in self.calls if m == "gettxout"], [["33" * 32, 0, True]])

    def test_spent_or_unavailable_successor_refuses(self):
        self.unspent = None
        with self.assertRaises(ValueError):
            self.verify()

    def test_insufficient_confirmations_refuse(self):
        self.policy["min_confirmations"] = 152
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(any(m == "gettxout" for m, p in self.calls))

    def test_orphaned_inclusion_refuses(self):
        self.header["confirmations"] = -1
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_genesis_refuses_before_backing_query(self):
        original = self.rpc

        def changed(method, params):
            return (
                "aa" * 32
                if method == "getblockhash" and params == [0]
                else original(method, params)
            )

        with self.assertRaises(ValueError):
            evidence.verify_bitcoin_backing(changed, self.facts, **self.policy)
        self.assertEqual(self.calls, [])

    def test_syncing_or_wrong_network_refuses(self):
        for mutation in (
            {"chain": "main"},
            {"initialblockdownload": True},
            {"headers": 201},
            {"blocks": True},
        ):
            with self.subTest(mutation=mutation):
                original = dict(self.info)
                self.info.update(mutation)
                with self.assertRaises(ValueError):
                    self.verify()
                self.info = original

    def test_wrong_parent_refuses(self):
        self.tx["vin"][0]["txid"] = "bb" * 32
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_exact_transaction_refuses(self):
        for key, value in (
            ("txid", "cc" * 32),
            ("blockhash", "dd" * 32),
            ("in_active_chain", False),
        ):
            original = self.tx[key]
            self.tx[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.verify()
            self.tx[key] = original

    def test_wrong_script_or_value_refuses(self):
        for source in (self.tx["vout"][0], self.unspent):
            original = source["value"]
            for value in (True, "0.12345678", 0.12345677, float("nan"), float("inf"), 0.000000001):
                source["value"] = value
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.verify()
            source["value"] = original
            source["scriptPubKey"]["hex"] = "5120" + "ff" * 32
            with self.assertRaises(ValueError):
                self.verify()
            source["scriptPubKey"]["hex"] = self.facts["custody_script_hex"]

    def test_reorg_during_sampling_refuses(self):
        self.after = dict(self.info, bestblockhash="aa" * 32)
        with self.assertRaises(ValueError):
            self.verify()

    def test_strict_native_facts(self):
        for key, value in (
            ("version", True),
            ("reserve_vout", -1),
            ("reserve_value_sats", "123"),
            ("operation", "PAYOUT"),
            ("direct_parent_txids", []),
            ("deposit_outpoint", "33" * 32 + ":01"),
            ("unknown", 1),
        ):
            facts = dict(self.facts, **{key: value})
            with self.subTest(field=key), self.assertRaises(ValueError):
                evidence.validate_backing_facts(facts)

    def test_pin_schema_is_not_coerced(self):
        for field, value in (
            ("min_confirmations", True),
            ("min_confirmations", 0),
            ("expected_genesis", "0" * 64),
            ("expected_network", []),
        ):
            policy = dict(self.policy, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.verify_bitcoin_backing(self.rpc, self.facts, **policy)

    def test_decimal_values_remain_exact(self):
        self.tx["vout"][0]["value"] = Decimal("0.12345678")
        self.unspent["value"] = Decimal("0.12345678")
        self.assertEqual(self.verify()["reserve_value_sats"], 12345678)

    def test_composed_inspection_rechecks_the_entire_native_frame(self):
        native = {"fixture_frame": 1}
        with (
            mock.patch.object(evidence, "inspect_fresh_mint", return_value=native) as inspect,
            mock.patch.object(evidence, "decode_backing_facts", return_value=self.facts),
        ):
            result = evidence.inspect_independent_backing(
                mock.Mock(),
                self.rpc,
                "fixture-keygen",
                "fixture-script",
                "fixture-template",
                mint_policy={},
                bitcoin_policy=self.policy,
            )
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(result["kind"], "rtp1-independent-backing")
        self.assertEqual(len(result["evidence_sha256"]), 64)
        self.assertEqual(result["transition"], self.facts)

    def test_native_change_during_bitcoin_checks_refuses(self):
        with (
            mock.patch.object(evidence, "inspect_fresh_mint", side_effect=[{"tip": 1}, {"tip": 2}]),
            mock.patch.object(evidence, "decode_backing_facts", return_value=self.facts),
            self.assertRaises(ValueError),
        ):
            evidence.inspect_independent_backing(
                mock.Mock(),
                self.rpc,
                "fixture-keygen",
                "fixture-script",
                "fixture-template",
                mint_policy={},
                bitcoin_policy=self.policy,
            )


if __name__ == "__main__":
    unittest.main()
