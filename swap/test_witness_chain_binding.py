"""Witness intended-chain checks using disposable in-memory RPC fixtures."""

import copy
import io
import json
import sys
import unittest
from unittest import mock

import veld_wt_reserve as witness
import test_chain_identity as chain_fixture

CHAIN = chain_fixture.CHAIN


class WitnessChainBindingTests(unittest.TestCase):
    def config(self):
        return {
            "url": "http://127.0.0.1:38374",
            "expected_chain": copy.deepcopy(CHAIN),
            "token_file": "/disposable/witness-token",
        }

    def test_matching_node_and_fresh_second_check(self):
        _, calls, call = chain_fixture.ChainIdentityTests().node()
        with (
            mock.patch.object(witness, "read_bounded_secret_file", return_value=b"fixture-token"),
            mock.patch.object(witness.VeldRpc, "call", side_effect=call),
        ):
            rpc = witness.VeldRpc(self.config())
            self.assertEqual(len(calls), 4)
            rpc.verify_chain_identity()
            self.assertEqual(len(calls), 8)

    def test_missing_pins_refused_before_token_read(self):
        cfg = self.config()
        del cfg["expected_chain"]
        with mock.patch.object(witness, "read_bounded_secret_file") as read:
            with self.assertRaisesRegex(ValueError, "expected_chain"):
                witness.VeldRpc(cfg)
        read.assert_not_called()

    def test_bounded_token_command_works_with_disposable_output(self):
        _, calls, call = chain_fixture.ChainIdentityTests().node()
        cfg = self.config()
        del cfg["token_file"]
        cfg["token_cmd"] = [sys.executable, "-c", "print('fixture-command-token')"]
        with mock.patch.object(witness.VeldRpc, "call", side_effect=call):
            rpc = witness.VeldRpc(cfg)
        self.assertEqual(rpc.token, "fixture-command-token")
        self.assertEqual(len(calls), 4)

    def test_changed_chain_cannot_reuse_constructor_success(self):
        answers, _, call = chain_fixture.ChainIdentityTests().node()
        with (
            mock.patch.object(witness, "read_bounded_secret_file", return_value=b"fixture-token"),
            mock.patch.object(witness.VeldRpc, "call", side_effect=call),
        ):
            rpc = witness.VeldRpc(self.config())
            answers[("getblockhash", (1,))] = "ef" * 32
            with self.assertRaisesRegex(ValueError, "launch"):
                rpc.verify_chain_identity()

    def test_failed_identity_prevents_mutable_state_on_both_entry_points(self):
        cfg = {"production": True, "veld_rpc": self.config()}
        for action in ("reserve", "commit"):
            with (
                self.subTest(action=action),
                mock.patch.object(
                    witness.sys,
                    "stdin",
                    mock.Mock(buffer=io.BytesIO(json.dumps({"action": action}).encode())),
                ),
                mock.patch.object(witness, "_secure_file"),
                mock.patch.object(witness, "_read_text_nofollow", return_value=json.dumps(cfg)),
                mock.patch.object(witness, "VeldRpc", side_effect=ValueError("intended chain")),
                mock.patch.object(witness, "_paths") as paths,
            ):
                with self.assertRaisesRegex(ValueError, "intended chain"):
                    witness.main()
                paths.assert_not_called()
        with (
            mock.patch.object(witness, "_secure_file"),
            mock.patch.object(witness, "_read_text_nofollow", return_value=json.dumps(cfg)),
            mock.patch.object(witness, "VeldRpc", side_effect=ValueError("intended chain")),
            mock.patch.object(witness, "_paths") as paths,
        ):
            for initialize in (False, True):
                with self.assertRaisesRegex(ValueError, "intended chain"):
                    witness.allocation_main(initialize=initialize)
            paths.assert_not_called()


if __name__ == "__main__":
    unittest.main()
