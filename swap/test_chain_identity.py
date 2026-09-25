"""Offline correctness checks using disposable chain identities."""

import copy
import unittest

from veld_chain_identity import parse_expected_chain, verify_expected_chain


CHAIN = {
    "profile_id": "private-qualification",
    "consensus_build_profile": "l3-regtest-fixed-difficulty-v1",
    "disposable": True,
    "external_value": False,
    "fixed_difficulty_regtest": True,
    "genesis_hash": "ab" * 32,
    "launch_block_hash": "cd" * 32,
}


class ChainIdentityTests(unittest.TestCase):
    def node(self, **overrides):
        answers = {
            ("getnetworkinfo", ()): dict(CHAIN),
            ("getcompiledgenesis", ()): CHAIN["genesis_hash"],
            ("getblockhash", (0,)): CHAIN["genesis_hash"],
            ("getblockhash", (1,)): CHAIN["launch_block_hash"],
        }
        answers[("getnetworkinfo", ())].update(overrides)
        calls = []

        def call(method, params):
            calls.append((method, tuple(params)))
            return answers[(method, tuple(params))]

        return answers, calls, call

    def test_matching_compiled_stored_and_launch_identity(self):
        _, calls, call = self.node()
        self.assertEqual(verify_expected_chain(call, CHAIN), CHAIN)
        self.assertEqual(len(calls), 4)

    def test_config_requires_every_pin_and_exact_types(self):
        for field in CHAIN:
            missing = dict(CHAIN)
            del missing[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_expected_chain(missing)
        for field in ("disposable", "external_value", "fixed_difficulty_regtest"):
            changed = dict(CHAIN, **{field: int(CHAIN[field])})
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_expected_chain(changed)
        for changed in (
            None,
            [],
            dict(CHAIN, unexpected=True),
            dict(CHAIN, genesis_hash="0" * 64),
            dict(CHAIN, launch_block_hash="REPLACE_WITH_REVIEWED_HASH"),
            dict(CHAIN, profile_id="REPLACE_WITH_REVIEWED_PROFILE_ID"),
        ):
            with self.subTest(config=changed), self.assertRaises(ValueError):
                parse_expected_chain(changed)

    def test_each_profile_pin_is_independent(self):
        alternatives = {
            "profile_id": "another-test-chain",
            "consensus_build_profile": "variable-difficulty-v1",
            "disposable": False,
            "external_value": True,
            "fixed_difficulty_regtest": False,
        }
        for field, value in alternatives.items():
            _, calls, call = self.node(**{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                verify_expected_chain(call, CHAIN)
            self.assertEqual(len(calls), 1)

    def test_stored_and_compiled_genesis_and_launch_are_independent(self):
        for key in (("getcompiledgenesis", ()), ("getblockhash", (0,)), ("getblockhash", (1,))):
            answers, _, call = self.node()
            answers[key] = "ef" * 32
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_expected_chain(call, CHAIN)

    def test_unavailable_identity_does_not_use_cached_results(self):
        answers, calls, call = self.node()
        self.assertEqual(verify_expected_chain(call, CHAIN), CHAIN)
        answers[("getnetworkinfo", ())] = None
        with self.assertRaisesRegex(ValueError, "unavailable"):
            verify_expected_chain(call, CHAIN)
        self.assertEqual(len(calls), 5)

    def test_expected_pins_are_not_rewritten_from_remote_identity(self):
        before = copy.deepcopy(CHAIN)
        answers, _, call = self.node()
        answers[("getblockhash", (1,))] = "ef" * 32
        with self.assertRaises(ValueError):
            verify_expected_chain(call, CHAIN)
        self.assertEqual(CHAIN, before)


if __name__ == "__main__":
    unittest.main()
