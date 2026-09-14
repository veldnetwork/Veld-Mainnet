import copy
import hashlib
import unittest
from types import SimpleNamespace
from unittest import mock

import rtp1_mint_policy as policy


class Rtp1MintPolicyTests(unittest.TestCase):
    def setUp(self):
        self.raw = "00"
        self.chain = {"profile_id": "isolated-fixture", "consensus_build_profile": "fixture",
            "disposable": True, "external_value": False, "fixed_difficulty_regtest": True,
            "genesis_hash": bytes(range(1, 33)).hex(), "launch_block_hash": "22" * 32}
        self.account = "V" + "1" * 30
        self.expected = {"expected_chain": self.chain, "issuer": self.account,
            "recipient": self.account, "sats": 20000, "custody_descriptor_sha256": "33" * 32,
            "custody_manifest_sha256": "44" * 32}
        self.response = {field: "55" * 32 for field in policy._HASH_FIELDS}
        self.response.update({"version": 1, "proof_version": "RTP1", "tip": 3000,
            "candidate_height": 3001, "final_height": 2980, "genesis_hash": self.chain["genesis_hash"],
            "unsigned_tx_sha256": hashlib.sha256(bytes.fromhex(self.raw)).hexdigest(),
            "issuer": self.account, "recipient": self.account, "sats": 20000,
            "fee_units": 100000, "deposit_outpoint": "66" * 32 + ":0",
            "reserve_prior_state_hex": "ab" * 200, "reserve_prior_supply_sats": 100000,
            "custody_descriptor_sha256": "33" * 32, "custody_manifest_sha256": "44" * 32})

    def validate(self, response=None, **updates):
        expected = dict(self.expected, **updates)
        return policy.validate_inspection(self.response if response is None else response,
                                          self.raw, **expected)

    def test_exact_inspection_is_copied(self):
        actual = self.validate()
        self.assertEqual(actual, self.response)
        self.assertIsNot(actual, self.response)

    def test_reversed_genesis_is_not_an_alternative_chain_pin(self):
        reversed_hash = bytes.fromhex(self.chain["genesis_hash"])[::-1].hex()
        self.assertNotEqual(reversed_hash, self.chain["genesis_hash"])
        with self.assertRaises(ValueError):
            self.validate(dict(self.response, genesis_hash=reversed_hash))

    def test_missing_custody_policy_is_not_inferred(self):
        with self.assertRaises(ValueError):
            self.validate(custody_descriptor_sha256="")

    def test_receipt_requires_exact_integer_fields(self):
        for field in ("version", "tip", "sats", "reserve_prior_supply_sats"):
            response = copy.deepcopy(self.response)
            response[field] = str(response[field])
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(response)

    def test_expected_chain_and_amount_are_not_replaced(self):
        with self.assertRaises(ValueError):
            self.validate(sats=20001)
        chain = dict(self.chain, genesis_hash="77" * 32)
        with self.assertRaises(ValueError):
            self.validate(expected_chain=chain)

    def test_native_tip_must_still_match(self):
        call = mock.Mock(side_effect=[self.response, 3001])
        with mock.patch.object(policy, "verify_expected_chain"), self.assertRaises(ValueError):
            policy.inspect_fresh_mint(call, self.raw, **self.expected)

    def test_pinned_chain_is_checked_before_inspection(self):
        call = mock.Mock(side_effect=[self.response, 3000, self.response["tip_hash"]])
        with mock.patch.object(policy, "verify_expected_chain") as verify:
            answer = policy.inspect_fresh_mint(call, self.raw, **self.expected)
        verify.assert_called_once_with(call, self.chain)
        self.assertEqual(answer, self.response)
        self.assertEqual(call.call_args_list[0], mock.call("inspectrtp1mint", [self.raw]))

    def test_rpc_unavailable_does_not_reuse_an_inspection(self):
        call = mock.Mock(side_effect=RuntimeError("fixture node stopped"))
        with mock.patch.object(policy, "verify_expected_chain"), self.assertRaises(RuntimeError):
            policy.inspect_fresh_mint(call, self.raw, **self.expected)

    def test_native_decoder_result_binds_exact_inspected_proof(self):
        import json
        proof = "ab" * 32
        self.response["proof_sha256"] = hashlib.sha256(bytes.fromhex(proof)).hexdigest()
        decoded = {"from": self.account, "to": self.account, "sats": 20000,
            "memo": "RTP1:" + proof, "total_out_sats": 123400, "num_inputs": 1}
        result = SimpleNamespace(returncode=0, stdout=json.dumps(decoded))
        with mock.patch.object(policy, "run_bounded_subprocess", return_value=result) as run:
            actual = policy.decode_inspected_mint("fixture-keygen", "76a914" + "11" * 20 + "88ac",
                self.raw, self.response, **self.expected)
        self.assertEqual(actual, decoded)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.kwargs["stdout_max"], 256 * 1024)
        self.assertEqual(run.call_args.args[0], ["fixture-keygen", "decode-mint-stdin"])
        request = json.loads(run.call_args.kwargs["input_text"])
        self.assertEqual(request["reserve_prior_state_hex"], self.response["reserve_prior_state_hex"])
        self.assertEqual(request["reserve_prior_supply_sats"], 100000)
        self.assertEqual(request["unsigned_tx_hex"], self.raw)

    def test_native_decoder_failure_is_not_an_authorization(self):
        result = SimpleNamespace(returncode=2, stdout="")
        with mock.patch.object(policy, "run_bounded_subprocess", return_value=result), self.assertRaises(ValueError):
            policy.decode_inspected_mint("fixture-keygen", "76a914" + "11" * 20 + "88ac",
                self.raw, self.response, **self.expected)

    def test_predicted_signed_size_refuses_before_issuance(self):
        import json
        decoded = {"from": self.account, "to": self.account, "sats": 20000,
            "memo": "RTP1:" + "ab" * 32, "total_out_sats": 100000, "num_inputs": 25}
        with mock.patch.object(policy, "run_bounded_subprocess", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(decoded))), \
                self.assertRaisesRegex(ValueError, "commit bound"):
            policy.decode_inspected_mint("fixture-keygen", "76a914" + "11" * 20 + "88ac", self.raw, self.response, **self.expected)


if __name__ == "__main__":
    unittest.main()
